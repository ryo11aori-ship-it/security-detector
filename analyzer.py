#!/usr/bin/env python3
import argparse
import base64
import collections
import dataclasses
import hashlib
import json
import logging
import math
import os
import re
import statistics
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import magic
except Exception:
    magic = None

try:
    import yara
except Exception:
    yara = None

try:
    import pefile
except Exception:
    pefile = None


@dataclasses.dataclass
class Finding:
    id: str
    title: str
    severity: str
    score: int
    evidence: Dict[str, Any]


class SafeFileReader:
    def __init__(self, max_bytes: int = 128 * 1024 * 1024):
        self.max_bytes = max_bytes

    def read_all(self, path: Path) -> bytes:
        size = path.stat().st_size
        if size > self.max_bytes:
            with path.open("rb") as f:
                return f.read(self.max_bytes)
        return path.read_bytes()


class CoreAnalyzer:
    def __init__(self):
        self.magic_handle = magic.Magic(mime=True) if magic else None

    def hashes(self, path: Path) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    def entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        counts = collections.Counter(data)
        length = len(data)
        value = 0.0

        for count in counts.values():
            p = count / length
            value -= p * math.log2(p)

        return round(value, 4)

    def byte_histogram_summary(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {}

        counts = collections.Counter(data)
        null_ratio = data.count(0) / len(data)
        printable_ratio = sum(1 for b in data if 32 <= b <= 126) / len(data)

        return {
            "unique_bytes": len(counts),
            "null_ratio": round(null_ratio, 4),
            "printable_ascii_ratio": round(printable_ratio, 4),
            "top_bytes": [
                {"byte": hex(byte), "count": count}
                for byte, count in counts.most_common(10)
            ],
        }

    def mime_type(self, path: Path) -> str:
        if self.magic_handle:
            try:
                return self.magic_handle.from_file(str(path))
            except Exception:
                pass

        suffix = path.suffix.lower()
        fallback = {
            ".exe": "application/x-dosexec",
            ".dll": "application/x-dosexec",
            ".sys": "application/x-dosexec",
            ".pdf": "application/pdf",
            ".zip": "application/zip",
            ".docm": "application/vnd.ms-word.document.macroEnabled.12",
            ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
            ".js": "text/javascript",
            ".vbs": "text/vbscript",
            ".ps1": "text/x-powershell",
            ".py": "text/x-python",
            ".sh": "text/x-shellscript",
        }
        return fallback.get(suffix, "application/octet-stream")

    def analyze(self, path: Path, data: bytes) -> Dict[str, Any]:
        st = path.stat()
        return {
            "path": str(path),
            "name": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": st.st_size,
            "mtime": int(st.st_mtime),
            "mime_type": self.mime_type(path),
            "hashes": self.hashes(path),
            "entropy": self.entropy(data),
            "byte_profile": self.byte_histogram_summary(data),
        }


class StringAnalyzer:
    ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
    UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

    SUSPICIOUS_PATTERNS = {
        "url": rb"https?://[^\s\"'>]+",
        "ipv4": rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "powershell": rb"powershell|pwsh|EncodedCommand|FromBase64String",
        "cmd": rb"cmd\.exe|/c\s+|/k\s+",
        "wscript": rb"wscript|cscript|mshta",
        "download": rb"DownloadString|DownloadFile|URLDownloadToFile|WinHttp|MSXML2\.XMLHTTP",
        "persistence": rb"Run\\|RunOnce\\|Startup|schtasks|CreateService|reg add",
        "injection": rb"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx",
        "credential": rb"password|passwd|credential|token|secret|apikey|api_key",
        "crypto": rb"CryptEncrypt|CryptDecrypt|BCrypt|AES|RC4|ChaCha|RSA",
        "anti_debug": rb"IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess",
    }

    def extract_ascii(self, data: bytes, limit: int = 3000) -> List[str]:
        result = []
        for m in self.ASCII_RE.finditer(data):
            s = m.group(0).decode("utf-8", "ignore")
            result.append(s)
            if len(result) >= limit:
                break
        return result

    def extract_utf16(self, data: bytes, limit: int = 1000) -> List[str]:
        result = []
        for m in self.UTF16_RE.finditer(data):
            try:
                s = m.group(0).decode("utf-16le", "ignore")
                result.append(s)
            except Exception:
                pass
            if len(result) >= limit:
                break
        return result

    def analyze(self, data: bytes) -> Dict[str, Any]:
        ascii_strings = self.extract_ascii(data)
        utf16_strings = self.extract_utf16(data)
        combined = "\n".join(ascii_strings + utf16_strings).encode("utf-8", "ignore")

        hits = {}
        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            found = re.findall(pattern, combined, flags=re.IGNORECASE)
            if found:
                hits[name] = min(len(found), 100)

        notable = []
        for s in ascii_strings + utf16_strings:
            lowered = s.lower()
            if any(k in lowered for k in [
                "powershell", "http://", "https://", "cmd.exe", "wscript",
                "virtualalloc", "writeprocessmemory", "createremotethread",
                "encodedcommand", "frombase64string"
            ]):
                notable.append(s[:300])
            if len(notable) >= 80:
                break

        return {
            "ascii_count": len(ascii_strings),
            "utf16_count": len(utf16_strings),
            "pattern_hits": hits,
            "notable_strings": notable,
        }


class PEAnalyzer:
    SUSPICIOUS_IMPORTS = {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "OpenProcess", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW",
        "RegSetValueA", "RegSetValueW", "RegCreateKeyA", "RegCreateKeyW",
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    }

    def is_pe(self, data: bytes) -> bool:
        return data[:2] == b"MZ"

    def analyze(self, path: Path) -> Dict[str, Any]:
        if not pefile:
            return {"available": False, "error": "pefile is not installed"}

        try:
            pe = pefile.PE(str(path), fast_load=False)
        except Exception as e:
            return {"available": False, "error": str(e)}

        result: Dict[str, Any] = {
            "available": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", None),
            "dll_characteristics": hex(getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)),
            "sections": [],
            "imports": {},
            "suspicious_imports": [],
            "has_debug": hasattr(pe, "DIRECTORY_ENTRY_DEBUG"),
            "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "has_resources": hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"),
            "is_signed_hint": False,
        }

        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", "ignore")
            raw = section.get_data()
            entropy = self._entropy(raw)
            flags = int(section.Characteristics)

            result["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 4),
                "characteristics": hex(flags),
                "executable": bool(flags & 0x20000000),
                "writable": bool(flags & 0x80000000),
            })

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            suspicious = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", "ignore") if entry.dll else "unknown"
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", "ignore")
                        funcs.append(name)
                        if name in self.SUSPICIOUS_IMPORTS:
                            suspicious.add(name)
                result["imports"][dll] = funcs
            result["suspicious_imports"] = sorted(suspicious)

        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if security_dir.VirtualAddress and security_dir.Size:
            result["is_signed_hint"] = True

        return result

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = collections.Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())


class ScriptAnalyzer:
    SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".py", ".sh"}

    PATTERNS = {
        "base64_decode": r"FromBase64String|base64\.b64decode|atob\(",
        "encoded_command": r"-enc\s+|-encodedcommand",
        "download_exec": r"DownloadString|curl\s+|wget\s+|Invoke-WebRequest|iwr\s+",
        "eval_exec": r"\beval\s*\(|exec\s*\(|IEX\s+|Invoke-Expression",
        "shell_spawn": r"subprocess|os\.system|child_process|WScript\.Shell|cmd\.exe|powershell",
        "persistence": r"RunOnce|CurrentVersion\\Run|schtasks|crontab|launchctl|Startup",
        "obfuscation": r"\$[a-zA-Z0-9_]{1,2}\s*=|chr\(|String\.fromCharCode|replace\(|split\(|join\(",
    }

    def should_analyze(self, path: Path, mime_type: str) -> bool:
        return path.suffix.lower() in self.SCRIPT_EXTENSIONS or mime_type.startswith("text/")

    def analyze(self, data: bytes) -> Dict[str, Any]:
        text = data.decode("utf-8", "ignore")
        hits = {}

        for name, pattern in self.PATTERNS.items():
            found = re.findall(pattern, text, flags=re.IGNORECASE)
            if found:
                hits[name] = len(found)

        long_lines = [len(line) for line in text.splitlines() if len(line) > 500]
        base64_blobs = re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", text)

        return {
            "line_count": text.count("\n") + 1 if text else 0,
            "max_line_length": max([len(x) for x in text.splitlines()] or [0]),
            "long_line_count": len(long_lines),
            "base64_blob_count": len(base64_blobs),
            "pattern_hits": hits,
        }


class ArchiveAnalyzer:
    def is_zip_like(self, path: Path, data: bytes) -> bool:
        return data[:4] == b"PK\x03\x04" or path.suffix.lower() in {
            ".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"
        }

    def analyze(self, path: Path) -> Dict[str, Any]:
        try:
            with zipfile.ZipFile(path, "r") as z:
                infos = z.infolist()
                names = [i.filename for i in infos]
                total_uncompressed = sum(i.file_size for i in infos)
                total_compressed = sum(i.compress_size for i in infos)
                suspicious_names = [
                    n for n in names
                    if n.lower().endswith((".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr"))
                    or "vbaProject.bin".lower() in n.lower()
                    or n.startswith("../")
                    or "/../" in n
                ]
                ratio = (
                    total_uncompressed / total_compressed
                    if total_compressed > 0 else None
                )

                return {
                    "is_archive": True,
                    "file_count": len(infos),
                    "total_uncompressed_size": total_uncompressed,
                    "total_compressed_size": total_compressed,
                    "compression_ratio": round(ratio, 2) if ratio else None,
                    "suspicious_entries": suspicious_names[:100],
                    "sample_entries": names[:80],
                }
        except Exception as e:
            return {"is_archive": False, "error": str(e)}


class YaraScanner:
    def __init__(self, rule_path: Optional[Path]):
        self.rule_path = rule_path
        self.rules = None
        self.error = None
        self._compile()

    def _compile(self):
        if not self.rule_path:
            return
        if not yara:
            self.error = "yara-python is not installed"
            return
        if not self.rule_path.exists():
            self.error = "YARA rule path does not exist"
            return

        try:
            if self.rule_path.is_file():
                self.rules = yara.compile(filepath=str(self.rule_path))
            else:
                files = {}
                for p in self.rule_path.rglob("*"):
                    if p.suffix.lower() in {".yar", ".yara"}:
                        files[str(p)] = str(p)
                if files:
                    self.rules = yara.compile(filepaths=files)
                else:
                    self.error = "No .yar/.yara files found"
        except Exception as e:
            self.error = str(e)

    def scan(self, path: Path) -> Dict[str, Any]:
        if not self.rules:
            return {"available": False, "error": self.error or "No YARA rules loaded"}

        try:
            matches = self.rules.match(str(path), timeout=15)
            return {
                "available": True,
                "matches": [
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": list(m.tags),
                        "meta": dict(m.meta),
                    }
                    for m in matches
                ],
            }
        except Exception as e:
            return {"available": False, "error": str(e)}


class HeuristicRiskEngine:
    def score(self, report: Dict[str, Any]) -> Tuple[int, str, List[Finding]]:
        findings: List[Finding] = []

        core = report.get("core", {})
        entropy = core.get("entropy", 0)
        size = core.get("size_bytes", 0)
        ext = core.get("extension", "")
        mime = core.get("mime_type", "")

        if entropy >= 7.2 and size > 2048:
            findings.append(Finding(
                "HIGH_ENTROPY",
                "High entropy content, possible packing/encryption/compression",
                "medium",
                15,
                {"entropy": entropy},
            ))

        strings = report.get("strings", {})
        string_hits = strings.get("pattern_hits", {})

        for key, points in {
            "powershell": 12,
            "download": 12,
            "persistence": 14,
            "injection": 18,
            "anti_debug": 10,
            "credential": 8,
        }.items():
            if key in string_hits:
                findings.append(Finding(
                    f"STRING_{key.upper()}",
                    f"Suspicious string pattern detected: {key}",
                    "medium",
                    points,
                    {"count": string_hits[key]},
                ))

        pe = report.get("pe", {})
        if pe.get("available"):
            suspicious_imports = pe.get("suspicious_imports", [])
            if suspicious_imports:
                findings.append(Finding(
                    "PE_SUSPICIOUS_IMPORTS",
                    "PE imports contain security-sensitive APIs",
                    "high",
                    min(30, 5 + len(suspicious_imports) * 3),
                    {"imports": suspicious_imports[:50]},
                ))

            for s in pe.get("sections", []):
                if s.get("entropy", 0) >= 7.2 and s.get("executable"):
                    findings.append(Finding(
                        "PE_PACKED_EXEC_SECTION",
                        "Executable PE section has high entropy",
                        "high",
                        18,
                        {"section": s},
                    ))
                if s.get("executable") and s.get("writable"):
                    findings.append(Finding(
                        "PE_RWX_SECTION",
                        "PE section is both writable and executable",
                        "high",
                        20,
                        {"section": s},
                    ))

            if pe.get("has_tls"):
                findings.append(Finding(
                    "PE_TLS_CALLBACK",
                    "PE has TLS directory, sometimes used for early execution",
                    "low",
                    6,
                    {},
                ))

            if not pe.get("is_signed_hint"):
                findings.append(Finding(
                    "PE_UNSIGNED",
                    "PE file does not appear to contain an Authenticode signature",
                    "low",
                    5,
                    {},
                ))

        script = report.get("script", {})
        if script.get("pattern_hits"):
            for name, count in script["pattern_hits"].items():
                weight = {
                    "base64_decode": 12,
                    "encoded_command": 18,
                    "download_exec": 18,
                    "eval_exec": 16,
                    "shell_spawn": 10,
                    "persistence": 16,
                    "obfuscation": 8,
                }.get(name, 5)
                findings.append(Finding(
                    f"SCRIPT_{name.upper()}",
                    f"Suspicious script behavior pattern: {name}",
                    "medium",
                    weight,
                    {"count": count},
                ))

        if script.get("base64_blob_count", 0) >= 1:
            findings.append(Finding(
                "SCRIPT_BASE64_BLOBS",
                "Large Base64-like blobs found in script/text",
                "medium",
                min(20, 8 + script["base64_blob_count"] * 4),
                {"count": script["base64_blob_count"]},
            ))

        archive = report.get("archive", {})
        if archive.get("is_archive"):
            suspicious_entries = archive.get("suspicious_entries", [])
            if suspicious_entries:
                findings.append(Finding(
                    "ARCHIVE_SUSPICIOUS_ENTRIES",
                    "Archive contains potentially risky embedded files or macro artifacts",
                    "medium",
                    min(25, 8 + len(suspicious_entries) * 3),
                    {"entries": suspicious_entries[:50]},
                ))

            ratio = archive.get("compression_ratio")
            if ratio and ratio > 100:
                findings.append(Finding(
                    "ARCHIVE_HIGH_COMPRESSION_RATIO",
                    "Archive has very high compression ratio",
                    "medium",
                    12,
                    {"compression_ratio": ratio},
                ))

        yara_result = report.get("yara", {})
        yara_matches = yara_result.get("matches", [])
        if yara_matches:
            findings.append(Finding(
                "YARA_MATCH",
                "One or more YARA rules matched",
                "critical",
                min(45, 20 + len(yara_matches) * 8),
                {"matches": yara_matches[:20]},
            ))

        risky_ext = {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".jar", ".docm", ".xlsm"}
        if ext in risky_ext:
            findings.append(Finding(
                "RISKY_FILE_TYPE",
                "File extension is commonly abused for executable or macro-capable content",
                "low",
                5,
                {"extension": ext, "mime_type": mime},
            ))

        total = min(100, sum(f.score for f in findings))

        if total >= 85:
            verdict = "critical"
        elif total >= 65:
            verdict = "high"
        elif total >= 35:
            verdict = "medium"
        elif total >= 15:
            verdict = "low"
        else:
            verdict = "minimal"

        return total, verdict, findings


class ExplanationEngine:
    def explain(self, score: int, verdict: str, findings: List[Finding]) -> Dict[str, Any]:
        ordered = sorted(findings, key=lambda f: f.score, reverse=True)

        if verdict in {"critical", "high"}:
            recommendation = "隔離して、信頼できる解析環境で追加確認してください。通常環境で開かないでください。"
        elif verdict == "medium":
            recommendation = "出所・署名・内容を確認し、必要なら隔離状態で追加解析してください。"
        elif verdict == "low":
            recommendation = "明確な悪性兆候は限定的ですが、出所不明なら注意してください。"
        else:
            recommendation = "静的解析上のリスクは低めです。ただし安全性を保証するものではありません。"

        return {
            "risk_score": score,
            "verdict": verdict,
            "summary": self._summary(score, verdict, ordered),
            "recommendation": recommendation,
            "top_reasons": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "score": f.score,
                    "evidence": f.evidence,
                }
                for f in ordered[:12]
            ],
            "limitations": [
                "このソフトは完全オフラインの静的解析のみを行います。",
                "検体を実行しないため、実行時挙動は確認しません。",
                "危険度は確率的・経験的な判定であり、マルウェア判定を保証しません。",
                "YARAルールの品質により検出精度が大きく変わります。",
            ],
        }

    def _summary(self, score: int, verdict: str, findings: List[Finding]) -> str:
        if not findings:
            return "明確な危険兆候は検出されませんでした。"

        main = findings[0].title
        return f"危険度は {score}/100、判定は {verdict} です。主な理由は「{main}」です。"


class OfflineFileRiskAnalyzer:
    def __init__(self, yara_rules: Optional[str] = None, max_bytes: int = 128 * 1024 * 1024):
        self.reader = SafeFileReader(max_bytes=max_bytes)
        self.core = CoreAnalyzer()
        self.strings = StringAnalyzer()
        self.pe = PEAnalyzer()
        self.script = ScriptAnalyzer()
        self.archive = ArchiveAnalyzer()
        self.yara = YaraScanner(Path(yara_rules)) if yara_rules else YaraScanner(None)
        self.risk = HeuristicRiskEngine()
        self.explain = ExplanationEngine()

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path).expanduser().resolve()

        if not path.exists():
            return {"error": "File not found", "path": str(path)}
        if not path.is_file():
            return {"error": "Target is not a regular file", "path": str(path)}

        started = time.time()
        data = self.reader.read_all(path)

        report: Dict[str, Any] = {
            "analyzer": {
                "name": "Offline File Risk Analyzer",
                "version": "2.0.0",
                "mode": "offline_static_only",
            },
            "core": self.core.analyze(path, data),
            "strings": self.strings.analyze(data),
            "yara": self.yara.scan(path),
        }

        mime_type = report["core"].get("mime_type", "")

        if self.pe.is_pe(data):
            report["pe"] = self.pe.analyze(path)
        else:
            report["pe"] = {"available": False, "reason": "Not a PE file"}

        if self.script.should_analyze(path, mime_type):
            report["script"] = self.script.analyze(data)
        else:
            report["script"] = {"available": False, "reason": "Not recognized as script/text"}

        if self.archive.is_zip_like(path, data):
            report["archive"] = self.archive.analyze(path)
        else:
            report["archive"] = {"is_archive": False}

        score, verdict, findings = self.risk.score(report)
        report["risk"] = self.explain.explain(score, verdict, findings)
        report["analysis_time_seconds"] = round(time.time() - started, 4)

        return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fully offline static file risk analyzer"
    )
    parser.add_argument("target", help="Target file path")
    parser.add_argument(
        "--yara-rules",
        default=None,
        help="Path to .yar/.yara file or directory",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=128 * 1024 * 1024,
        help="Maximum bytes to load for deep content analysis",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to file",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    analyzer = OfflineFileRiskAnalyzer(
        yara_rules=args.yara_rules,
        max_bytes=args.max_bytes,
    )

    report = analyzer.analyze_file(args.target)
    text = json.dumps(report, ensure_ascii=False, indent=2)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())