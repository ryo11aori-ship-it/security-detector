import argparse
import json
import os
import sys

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
except Exception:
    joblib = None
    RandomForestClassifier = None


class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            "size_bytes", "entropy", "null_ratio", "printable_ratio",
            "ascii_count", "utf16_count", "hit_powershell", "hit_download",
            "hit_persistence", "is_pe", "pe_sections", "pe_has_debug",
            "pe_is_signed", "pe_suspicious_imports"
        ]

    def extract(self, report: dict) -> list:
        vec = []
        core = report.get("core", {})
        vec.append(float(core.get("size_bytes", 0)))
        vec.append(float(core.get("entropy", 0.0)))

        byte_prof = core.get("byte_profile", {})
        vec.append(float(byte_prof.get("null_ratio", 0.0)))
        vec.append(float(byte_prof.get("printable_ascii_ratio", 0.0)))

        strings = report.get("strings", {})
        vec.append(float(strings.get("ascii_count", 0)))
        vec.append(float(strings.get("utf16_count", 0)))

        patterns = strings.get("pattern_hits", {})
        vec.append(float(patterns.get("powershell", 0)))
        vec.append(float(patterns.get("download", 0)))
        vec.append(float(patterns.get("persistence", 0)))

        pe = report.get("pe", {})
        vec.append(1.0 if pe.get("available") else 0.0)
        vec.append(float(pe.get("number_of_sections", 0)))
        vec.append(1.0 if pe.get("has_debug") else 0.0)
        vec.append(1.0 if pe.get("is_signed_hint") else 0.0)
        vec.append(float(len(pe.get("suspicious_imports", []))))

        return vec


class LocalMalwareAI:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None

    def load(self) -> bool:
        if not joblib or not os.path.exists(self.model_path):
            return False
        try:
            self.model = joblib.load(self.model_path)
            return True
        except Exception:
            return False

    def train_dummy_model(self):
        if self.load():
            return
        if not RandomForestClassifier:
            return
        
        # CI/CDを通過させるための仮の学習データ (0: 正常, 1: 危険)
        # 実際はここに数万件の特徴量配列を読み込ませます
        x_train = [
            [1000, 4.0, 0.1, 0.8, 50, 10, 0, 0, 0, 0, 0, 0, 0, 0],  # 正常なテキスト
            [50000, 7.8, 0.0, 0.2, 10, 2, 1, 1, 1, 1, 3, 0, 0, 5],  # ランサムウェア風
            [2048, 6.0, 0.2, 0.6, 100, 50, 0, 0, 0, 1, 5, 1, 1, 0], # 正常なexe
        ]
        y_train = [0, 1, 0]

        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(x_train, y_train)
        joblib.dump(self.model, self.model_path)

    def predict(self, feature_vector: list) -> dict:
        if not self.model:
            return {"error": "Model not loaded or scikit-learn missing"}
        try:
            # 危険(1)である確率を取得
            proba = self.model.predict_proba([feature_vector])[0]
            risk_score = int(proba[1] * 100)
            return {"ai_risk_score": risk_score, "status": "success"}
        except Exception as e:
            return {"error": str(e)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Malware AI Predictor")
    parser.add_argument("--report", required=True, help="JSON report from analyzer.py")
    parser.add_argument("--model", default="model_rf.pkl", help="Path to AI model")
    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(json.dumps({"error": f"Report not found: {args.report}"}))
        return 1

    with open(args.report, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    extractor = FeatureExtractor()
    features = extractor.extract(report_data)

    ai_engine = LocalMalwareAI(model_path=args.model)
    ai_engine.train_dummy_model()

    prediction = ai_engine.predict(features)

    output = {
        "ai_prediction": prediction,
        "extracted_vector": dict(zip(extractor.feature_names, features))
    }

    print(json.dumps(output, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
