#!/usr/bin/env python3
# ai_engine.py

import argparse
import dataclasses
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import joblib
except Exception:
    joblib = None

try:
    from sklearn.ensemble import RandomForestClassifier
except Exception:
    RandomForestClassifier = None


@dataclasses.dataclass(frozen=True)
class FeatureSpec:
    name: str
    default: float = 0.0


class FeatureExtractor:
    VERSION = "3.0.0"

    FEATURES = [
        FeatureSpec("log_size"),
        FeatureSpec("entropy"),
        FeatureSpec("null_ratio"),
        FeatureSpec("printable_ratio"),
        FeatureSpec("ascii_log_count"),
        FeatureSpec("utf16_log_count"),
        FeatureSpec("hit_powershell"),
        FeatureSpec("hit_download"),
        FeatureSpec("hit_persistence"),
        FeatureSpec("hit_injection"),
        FeatureSpec("hit_anti_debug"),
        FeatureSpec("is_pe"),
        FeatureSpec("pe_sections"),
        FeatureSpec("pe_has_debug"),
        FeatureSpec("pe_has_tls"),
        FeatureSpec("pe_is_signed"),
        FeatureSpec("pe_suspicious_imports"),
        FeatureSpec("pe_rwx_sections"),
        FeatureSpec("pe_high_entropy_exec_sections"),
        FeatureSpec("is_archive"),
        FeatureSpec("archive_suspicious_entries"),
        FeatureSpec("script_base64_blobs"),
        FeatureSpec("script_encoded_command"),
        FeatureSpec("script_download_exec"),
        FeatureSpec("script_eval_exec"),
        FeatureSpec("yara_match_count"),
        FeatureSpec("heuristic_risk_score"),
    ]

    @property
    def feature_names(self) -> List[str]:
        return [f.name for f in self.FEATURES]

    def extract(self, report: Dict[str, Any]) -> List[float]:
        core = report.get("core", {})
        byte_profile = core.get("byte_profile", {})
        strings = report.get("strings", {})
        patterns = strings.get("pattern_hits", {})
        pe = report.get("pe", {})
        archive = report.get("archive", {})
        script = report.get("script", {})
        script_hits = script.get("pattern_hits", {})
        yara_data = report.get("yara", {})
        risk = report.get("risk", {})

        pe_sections = pe.get("sections", []) if isinstance(pe.get("sections"), list) else []

        rwx_sections = sum(
            1 for s in pe_sections
            if s.get("executable") and s.get("writable")
        )

        high_entropy_exec_sections = sum(
            1 for s in pe_sections
            if s.get("executable") and float(s.get("entropy", 0.0)) >= 7.2
        )

        values = {
            "log_size": self._log1p(core.get("size_bytes", 0)),
            "entropy": self._float(core.get("entropy", 0.0)),
            "null_ratio": self._float(byte_profile.get("null_ratio", 0.0)),
            "printable_ratio": self._float(byte_profile.get("printable_ascii_ratio", 0.0)),
            "ascii_log_count": self._log1p(strings.get("ascii_count", 0)),
            "utf16_log_count": self._log1p(strings.get("utf16_count", 0)),
            "hit_powershell": self._cap(patterns.get("powershell", 0), 50),
            "hit_download": self._cap(patterns.get("download", 0), 50),
            "hit_persistence": self._cap(patterns.get("persistence", 0), 50),
            "hit_injection": self._cap(patterns.get("injection", 0), 50),
            "hit_anti_debug": self._cap(patterns.get("anti_debug", 0), 50),
            "is_pe": 1.0 if pe.get("available") else 0.0,
            "pe_sections": self._cap(pe.get("number_of_sections", 0), 30),
            "pe_has_debug": 1.0 if pe.get("has_debug") else 0.0,
            "pe_has_tls": 1.0 if pe.get("has_tls") else 0.0,
            "pe_is_signed": 1.0 if pe.get("is_signed_hint") else 0.0,
            "pe_suspicious_imports": self._cap(len(pe.get("suspicious_imports", [])), 80),
            "pe_rwx_sections": self._cap(rwx_sections, 20),
            "pe_high_entropy_exec_sections": self._cap(high_entropy_exec_sections, 20),
            "is_archive": 1.0 if archive.get("is_archive") else 0.0,
            "archive_suspicious_entries": self._cap(len(archive.get("suspicious_entries", [])), 100),
            "script_base64_blobs": self._cap(script.get("base64_blob_count", 0), 100),
            "script_encoded_command": self._cap(script_hits.get("encoded_command", 0), 50),
            "script_download_exec": self._cap(script_hits.get("download_exec", 0), 50),
            "script_eval_exec": self._cap(script_hits.get("eval_exec", 0), 50),
            "yara_match_count": self._cap(len(yara_data.get("matches", [])), 100),
            "heuristic_risk_score": self._float(risk.get("risk_score", 0)) / 100.0,
        }

        return [float(values.get(spec.name, spec.default)) for spec in self.FEATURES]

    def vector_as_dict(self, vector: List[float]) -> Dict[str, float]:
        return dict(zip(self.feature_names, vector))

    def _float(self, value: Any) -> float:
        try:
            v = float(value)
            if math.isnan(v) or math.isinf(v):
                return 0.0
            return v
        except Exception:
            return 0.0

    def _log1p(self, value: Any) -> float:
        return math.log1p(max(0.0, self._float(value)))

    def _cap(self, value: Any, maximum: float) -> float:
        return min(max(self._float(value), 0.0), maximum)


class LocalAIEngine:
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.model: Any = None
        self.metadata: Dict[str, Any] = {}

    def load(self, expected_features: List[str]) -> bool:
        if not joblib:
            self.metadata = {"error": "joblib is not installed"}
            return False

        if not self.model_path.exists():
            self.metadata = {"error": f"model not found: {self.model_path}"}
            return False

        try:
            payload = joblib.load(self.model_path)
        except Exception as e:
            self.metadata = {"error": f"failed to load model: {e}"}
            return False

        if isinstance(payload, dict) and "model" in payload:
            self.model = payload["model"]
            self.metadata = payload.get("metadata", {})
            feature_names = payload.get("feature_names", [])
        else:
            self.model = payload
            self.metadata = {"warning": "legacy model format without metadata"}
            feature_names = []

        if feature_names and list(feature_names) != list(expected_features):
            self.metadata = {
                **self.metadata,
                "error": "feature schema mismatch",
                "model_features": feature_names,
                "expected_features": expected_features,
            }
            self.model = None
            return False

        return True

    def predict(self, vector: List[float]) -> Dict[str, Any]:
        if self.model is None:
            return {
                "available": False,
                "error": self.metadata.get("error", "model not loaded"),
            }

        try:
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba([vector])[0]
                classes = list(getattr(self.model, "classes_", [0, 1]))

                if 1 in classes:
                    risk_probability = float(proba[classes.index(1)])
                else:
                    risk_probability = float(max(proba))

                return {
                    "available": True,
                    "ai_risk_score": int(round(risk_probability * 100)),
                    "risk_probability": round(risk_probability, 4),
                    "model_metadata": self.metadata,
                }

            prediction = int(self.model.predict([vector])[0])
            return {
                "available": True,
                "ai_risk_score": 100 if prediction == 1 else 0,
                "risk_probability": None,
                "model_metadata": self.metadata,
            }

        except Exception as e:
            return {
                "available": False,
                "error": str(e),
                "model_metadata": self.metadata,
            }


class RiskFusion:
    def fuse(self, report: Dict[str, Any], ai_result: Dict[str, Any]) -> Dict[str, Any]:
        heuristic = int(report.get("risk", {}).get("risk_score", 0))

        if not ai_result.get("available"):
            return {
                "final_risk_score": heuristic,
                "source": "heuristic_only",
                "verdict": self.verdict(heuristic),
                "note": "AI model unavailable; using heuristic score only.",
            }

        ai_score = int(ai_result.get("ai_risk_score", 0))

        # 保守的な融合: ルール判定を強め、AIを補助にする
        final_score = round((heuristic * 0.65) + (ai_score * 0.35))

        yara_matches = report.get("yara", {}).get("matches", [])
        if yara_matches:
            final_score = max(final_score, 75)

        pe = report.get("pe", {})
        if pe.get("available") and len(pe.get("suspicious_imports", [])) >= 8:
            final_score = max(final_score, 60)

        final_score = max(0, min(100, final_score))

        return {
            "final_risk_score": final_score,
            "source": "heuristic_ai_fusion",
            "heuristic_score": heuristic,
            "ai_score": ai_score,
            "verdict": self.verdict(final_score),
            "fusion_policy": "65% heuristic + 35% local ML, with conservative rule-based floors",
        }

    def verdict(self, score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 15:
            return "low"
        return "minimal"


def create_dummy_model(model_path: str) -> None:
    if not joblib or not RandomForestClassifier:
        raise RuntimeError("joblib and scikit-learn are required")

    extractor = FeatureExtractor()

    # CI・動作確認専用。実検体判定に使わない。
    x_train = [
        [math.log1p(1000), 4.0, 0.1, 0.8, math.log1p(50), math.log1p(10), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.05],
        [math.log1p(50000), 7.8, 0.0, 0.2, math.log1p(10), math.log1p(2), 1, 1, 1, 1, 1, 1, 3, 0, 0, 0, 5, 1, 1, 0, 0, 2, 1, 1, 1, 0, 0.85],
        [math.log1p(204800), 6.1, 0.2, 0.5, math.log1p(300), math.log1p(80), 0, 0, 0, 0, 0, 1, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.15],
        [math.log1p(4096), 5.5, 0.0, 0.9, math.log1p(200), math.log1p(0), 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0.70],
    ]
    y_train = [0, 1, 0, 1]

    model = RandomForestClassifier(
        n_estimators=50,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)

    payload = {
        "model": model,
        "feature_names": extractor.feature_names,
        "metadata": {
            "purpose": "dummy_model_for_ci_only",
            "feature_extractor_version": extractor.VERSION,
            "warning": "Do not use this model for real security decisions.",
        },
    }

    joblib.dump(payload, model_path)


def load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline local AI risk engine")
    parser.add_argument("--report", help="JSON report from offline_file_risk_analyzer.py")
    parser.add_argument("--model", default="model_rf.pkl")
    parser.add_argument("--create-dummy-model", action="store_true")
    parser.add_argument("--output", default=None)

    args = parser.parse_args()

    if args.create_dummy_model:
        create_dummy_model(args.model)
        print(json.dumps({
            "status": "created",
            "model": args.model,
            "warning": "Dummy model is for CI/testing only."
        }, indent=2))
        return 0

    if not args.report:
        print(json.dumps({"error": "--report is required"}, indent=2))
        return 2

    if not os.path.exists(args.report):
        print(json.dumps({"error": f"report not found: {args.report}"}, indent=2))
        return 1

    report = load_report(args.report)

    extractor = FeatureExtractor()
    vector = extractor.extract(report)

    engine = LocalAIEngine(args.model)
    engine.load(extractor.feature_names)
    ai_prediction = engine.predict(vector)

    fusion = RiskFusion().fuse(report, ai_prediction)

    output = {
        "engine": {
            "name": "Offline Local AI Engine",
            "version": "3.0.0",
            "mode": "offline_inference_only",
        },
        "ai_prediction": ai_prediction,
        "fusion": fusion,
        "features": extractor.vector_as_dict(vector),
    }

    text = json.dumps(output, ensure_ascii=False, indent=2)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())