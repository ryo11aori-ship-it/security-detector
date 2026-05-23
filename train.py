#!/usr/bin/env python3
import argparse
import os
import sys
import urllib.request
import random
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
def generate_dummy_data():
    print("CI/CD用のダミーデータを生成中...")
    data=[]
    for _ in range(50):
        data.append([332.0,224.0,random.uniform(258,271),5.0,random.uniform(5000,30000),random.uniform(320,9000),random.randint(3,6),random.uniform(3.5,6.2),random.uniform(4.5,6.8),random.randint(1,8),random.randint(10,100),random.randint(0,5),0])
    for _ in range(50):
        data.append([332.0,224.0,random.uniform(270,350),5.0,random.uniform(30000,200000),random.uniform(30000,50000),random.randint(5,12),random.uniform(6.4,7.9),random.uniform(7.0,8.0),random.randint(5,25),random.randint(100,500),random.randint(0,20),1])
    return pd.DataFrame(data,columns=FEATURES+["malicious"])
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--real",action="store_true")
    args=parser.parse_args()
    print("--- AIモデルの学習を開始 ---")
    if args.real:
        if not os.path.exists(CSV_FILE):
            print("データセットをダウンロード中...")
            urllib.request.urlretrieve(CSV_URL,CSV_FILE)
        try:
            df=pd.read_csv(CSV_FILE,sep="|")
            y=1-df["legitimate"]
        except Exception as e:
            print(f"CSVパースエラー: {e}")
            sys.exit(1)
    else:
        df=generate_dummy_data()
        y=df["malicious"]
    X=df[FEATURES]
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=42)
    model=RandomForestClassifier(n_estimators=50,max_depth=10,random_state=42)
    model.fit(X_train,y_train)
    acc=accuracy_score(y_test,model.predict(X_test))
    print(f"精度: {acc:.4f}")
    payload={"model":model,"feature_names":FEATURES,"metadata":{"purpose":"real_kaggle_dataset" if args.real else "ci_dummy","feature_extractor_version":"4.0.0_kaggle_compatible","test_accuracy":acc}}
    joblib.dump(payload,"model_rf.pkl")
    print("モデルを保存しました: model_rf.pkl")
if __name__=="__main__":
    main()
