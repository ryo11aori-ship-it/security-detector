#!/usr/bin/env python3
import os
import sys
import urllib.request

if sys.stdout.encoding.lower()!='utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

CSV_URL="https://raw.githubusercontent.com/mburakergenc/Malware-Detection-using-Machine-Learning/master/data.csv"
CSV_FILE="real_malware_dataset.csv"
FEATURES=["Machine","SizeOfOptionalHeader","Characteristics","MajorSubsystemVersion","SizeOfCode","DllCharacteristics","SectionsNb","SectionsMeanEntropy","SectionsMaxEntropy","ImportsNbDLL","ImportsNb","ExportNb"]

def main():
    print("--- リアル検体データを用いたAIモデルの学習を開始 ---")
    if not os.path.exists(CSV_FILE):
        print(f"データセットをダウンロード中 (約17MB)...")
        urllib.request.urlretrieve(CSV_URL,CSV_FILE)
        print("ダウンロード完了。")
    print("CSVデータを読み込み中...")
    df=pd.read_csv(CSV_FILE,sep="|")
    print(f"総データ数: {len(df)}件")
    X=df[FEATURES]
    y=df["legitimate"]
    y=1-y
    print("データを訓練用(80%)とテスト用(20%)に分割...")
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=42)
    print("RandomForestで学習を実行中...")
    model=RandomForestClassifier(n_estimators=100,max_depth=15,random_state=42,class_weight="balanced")
    model.fit(X_train,y_train)
    print("\nモデルの精度を評価中...")
    y_pred=model.predict(X_test)
    acc=accuracy_score(y_test,y_pred)
    print(f"テストデータでの正解率: {acc:.4f}")
    model_path="model_rf.pkl"
    payload={"model":model,"feature_names":FEATURES,"metadata":{"purpose":"trained_on_real_kaggle_dataset","feature_extractor_version":"4.0.0_kaggle_compatible","training_samples":len(df),"test_accuracy":acc}}
    joblib.dump(payload,model_path)
    print(f"\n実データ学習済みモデルを保存しました: {model_path}")

if __name__=="__main__":
    main()
