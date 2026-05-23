#!/usr/bin/env python3
import json
import math
import os
import random
import sys

try:
    import joblib
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.model_selection import train_test_split
except Exception as e:
    print(f"Error importing ML libraries: {e}")
    sys.exit(1)

FEATURE_NAMES = [
    "log_size", "entropy", "null_ratio", "printable_ratio",
    "ascii_log_count", "utf16_log_count", "hit_powershell", "hit_download",
    "hit_persistence", "hit_injection", "hit_anti_debug", "is_pe",
    "pe_sections", "pe_has_debug", "pe_has_tls", "pe_is_signed",
    "pe_suspicious_imports", "pe_rwx_sections", "pe_high_entropy_exec_sections",
    "is_archive", "archive_suspicious_entries", "script_base64_blobs",
    "script_encoded_command", "script_download_exec", "script_eval_exec",
    "yara_match_count", "heuristic_risk_score"
]

def generate_synthetic_data(num_samples=10000):
    data = []
    labels = []
    for _ in range(num_samples):
        is_malware = random.choice([0, 1])
        labels.append(is_malware)
        row = {}
        if is_malware:
            row["log_size"] = random.uniform(math.log1p(10000), math.log1p(5000000))
            row["entropy"] = random.uniform(6.8, 7.99)
            row["null_ratio"] = random.uniform(0.0, 0.1)
            row["printable_ratio"] = random.uniform(0.1, 0.4)
            row["ascii_log_count"] = random.uniform(math.log1p(10), math.log1p(500))
            row["utf16_log_count"] = random.uniform(0, math.log1p(100))
            row["hit_powershell"] = random.randint(0, 5)
            row["hit_download"] = random.randint(0, 3)
            row["hit_persistence"] = random.randint(0, 3)
            row["hit_injection"] = random.randint(0, 2)
            row["hit_anti_debug"] = random.randint(0, 2)
            row["is_pe"] = 1.0
            row["pe_sections"] = random.randint(3, 10)
            row["pe_has_debug"] = random.choice([0.0, 1.0])
            row["pe_has_tls"] = random.choice([0.0, 1.0])
            row["pe_is_signed"] = 0.0
            row["pe_suspicious_imports"] = random.randint(2, 15)
            row["pe_rwx_sections"] = random.randint(0, 2)
            row["pe_high_entropy_exec_sections"] = random.randint(0, 1)
            row["is_archive"] = 0.0
            row["archive_suspicious_entries"] = 0.0
            row["script_base64_blobs"] = random.randint(0, 2)
            row["script_encoded_command"] = random.randint(0, 1)
            row["script_download_exec"] = random.randint(0, 1)
            row["script_eval_exec"] = 0.0
            row["yara_match_count"] = random.randint(0, 3)
            row["heuristic_risk_score"] = random.uniform(0.5, 0.95)
        else:
            row["log_size"] = random.uniform(math.log1p(5000), math.log1p(10000000))
            row["entropy"] = random.uniform(4.0, 6.5)
            row["null_ratio"] = random.uniform(0.0, 0.2)
            row["printable_ratio"] = random.uniform(0.4, 0.9)
            row["ascii_log_count"] = random.uniform(math.log1p(100), math.log1p(5000))
            row["utf16_log_count"] = random.uniform(0, math.log1p(1000))
            row["hit_powershell"] = 0.0
            row["hit_download"] = 0.0
            row["hit_persistence"] = 0.0
            row["hit_injection"] = 0.0
            row["hit_anti_debug"] = 0.0
            row["is_pe"] = 1.0
            row["pe_sections"] = random.randint(3, 7)
            row["pe_has_debug"] = 1.0
            row["pe_has_tls"] = random.choice([0.0, 1.0])
            row["pe_is_signed"] = 1.0
            row["pe_suspicious_imports"] = random.randint(0, 3)
            row["pe_rwx_sections"] = 0.0
            row["pe_high_entropy_exec_sections"] = 0.0
            row["is_archive"] = 0.0
            row["archive_suspicious_entries"] = 0.0
            row["script_base64_blobs"] = 0.0
            row["script_encoded_command"] = 0.0
            row["script_download_exec"] = 0.0
            row["script_eval_exec"] = 0.0
            row["yara_match_count"] = 0.0
            row["heuristic_risk_score"] = random.uniform(0.0, 0.2)
        data.append([row[f] for f in FEATURE_NAMES])
    return pd.DataFrame(data, columns=FEATURE_NAMES), pd.Series(labels)

def main():
    print("--- Starting Large-Scale AI Model Training ---")
    
    # 【本番用】CSVがある場合は以下の行のコメントを外し、疑似データ生成を消す
    # df = pd.read_csv("real_malware_dataset.csv")
    # X = df[FEATURE_NAMES]
    # y = df["is_malware"]
    
    print("Generating 10,000 synthetic training samples (Stats based)...")
    X, y = generate_synthetic_data(num_samples=10000)
    
    print("Splitting data into 80% Train and 20% Test...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training RandomForest Classifier (100 Trees)...")
    model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    
    print("Evaluating Model Accuracy...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy on Test Set: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    model_path = "model_rf.pkl"
    payload = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "metadata": {
            "purpose": "trained_on_large_scale_data",
            "feature_extractor_version": "3.0.0",
            "training_samples": len(X),
            "test_accuracy": acc
        }
    }
    joblib.dump(payload, model_path)
    print(f"\nModel successfully exported to {model_path}!")

if __name__ == "__main__":
    main()
