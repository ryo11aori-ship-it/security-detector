#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any,Dict,List
try:
    import joblib
except Exception:
    joblib=None
try:
    import pefile
except Exception:
    pefile=None
class KaggleFeatureExtractor:
    VERSION="4.0.0_kaggle_compatible"
    FEATURES=["Machine","SizeOfOptionalHeader","Characteristics","MajorSubsystemVersion","SizeOfCode","DllCharacteristics","SectionsNb","SectionsMeanEntropy","SectionsMaxEntropy","ImportsNbDLL","ImportsNb","ExportNb"]
    @property
    def feature_names(self)->List[str]:
        return self.FEATURES
    def extract(self,file_path:str)->List[float]:
        if not pefile or not os.path.exists(file_path):
            return [0.0]*len(self.FEATURES)
        try:
            pe=pefile.PE(file_path,fast_load=False)
        except Exception:
            return [0.0]*len(self.FEATURES)
        machine=pe.FILE_HEADER.Machine
        size_opt=pe.FILE_HEADER.SizeOfOptionalHeader
        chars=pe.FILE_HEADER.Characteristics
        maj_sub=pe.OPTIONAL_HEADER.MajorSubsystemVersion
        size_code=pe.OPTIONAL_HEADER.SizeOfCode
        dll_chars=pe.OPTIONAL_HEADER.DllCharacteristics
        sec_nb=pe.FILE_HEADER.NumberOfSections
        entropies=[s.get_entropy() for s in pe.sections]
        sec_mean_ent=sum(entropies)/len(entropies) if entropies else 0.0
        sec_max_ent=max(entropies) if entropies else 0.0
        imports_dll=0
        imports_nb=0
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            imports_dll=len(pe.DIRECTORY_ENTRY_IMPORT)
            imports_nb=sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        export_nb=0
        if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
            export_nb=len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        return [float(machine),float(size_opt),float(chars),float(maj_sub),float(size_code),float(dll_chars),float(sec_nb),float(sec_mean_ent),float(sec_max_ent),float(imports_dll),float(imports_nb),float(export_nb)]
    def vector_as_dict(self,vector:List[float])->Dict[str,float]:
        return dict(zip(self.feature_names,vector))
class LocalAIEngine:
    def __init__(self,model_path:str):
        self.model_path=Path(model_path)
        self.model:Any=None
        self.metadata:Dict[str,Any]={}
    def load(self,expected_features:List[str])->bool:
        if not joblib:
            self.metadata={"error":"joblib is not installed"}
            return False
        if not self.model_path.exists():
            self.metadata={"error":f"model not found: {self.model_path}"}
            return False
        try:
            payload=joblib.load(self.model_path)
            self.model=payload["model"]
            self.metadata=payload.get("metadata",{})
            feature_names=payload.get("feature_names",[])
        except Exception as e:
            self.metadata={"error":f"failed to load model: {e}"}
            return False
        if list(feature_names)!=list(expected_features):
            self.metadata={"error":"feature schema mismatch"}
            self.model=None
            return False
        return True
    def predict(self,vector:List[float])->Dict[str,Any]:
        if self.model is None:
            return {"available":False,"error":self.metadata.get("error","model not loaded")}
        try:
            proba=self.model.predict_proba([vector])[0]
            classes=list(getattr(self.model,"classes_",[0,1]))
            risk_probability=float(proba[classes.index(1)]) if 1 in classes else float(max(proba))
            return {"available":True,"ai_risk_score":int(round(risk_probability*100)),"risk_probability":round(risk_probability,4),"model_metadata":self.metadata}
        except Exception as e:
            return {"available":False,"error":str(e),"model_metadata":self.metadata}
class RiskFusion:
    def fuse(self,report:Dict[str,Any],ai_result:Dict[str,Any])->Dict[str,Any]:
        heuristic=int(report.get("risk",{}).get("risk_score",0))
        if not ai_result.get("available"):
            return {"final_risk_score":heuristic,"source":"heuristic_only","verdict":self.verdict(heuristic),"note":"AI model unavailable"}
        ai_score=int(ai_result.get("ai_risk_score",0))
        final_score=round((heuristic*0.5)+(ai_score*0.5))
        yara_matches=report.get("yara",{}).get("matches",[])
        if yara_matches:
            final_score=max(final_score,75)
        final_score=max(0,min(100,final_score))
        purpose=ai_result.get("model_metadata",{}).get("purpose","unknown")
        policy="50% heuristic + 50% CI Dummy AI" if purpose=="ci_dummy" else "50% heuristic + 50% Real-Data AI"
        return {"final_risk_score":final_score,"source":"heuristic_ai_fusion","heuristic_score":heuristic,"ai_score":ai_score,"verdict":self.verdict(final_score),"fusion_policy":policy}
    def verdict(self,score:int)->str:
        if score>=85: return "critical"
        if score>=65: return "high"
        if score>=35: return "medium"
        if score>=15: return "low"
        return "minimal"
def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--report",required=True)
    parser.add_argument("--target",required=True)
    parser.add_argument("--model",default="model_rf.pkl")
    parser.add_argument("--output",default=None)
    args=parser.parse_args()
    if not os.path.exists(args.report):
        print(json.dumps({"error":f"report not found: {args.report}"}))
        return 1
    with open(args.report,"r",encoding="utf-8") as f:
        report=json.load(f)
    extractor=KaggleFeatureExtractor()
    vector=extractor.extract(args.target)
    engine=LocalAIEngine(args.model)
    engine.load(extractor.feature_names)
    ai_prediction=engine.predict(vector)
    fusion=RiskFusion().fuse(report,ai_prediction)
    output={"engine":{"name":"Offline Local AI Engine","version":"4.1.0","mode":"inference"},"ai_prediction":ai_prediction,"fusion":fusion,"features":extractor.vector_as_dict(vector)}
    text=json.dumps(output,ensure_ascii=False,indent=2)
    if args.output:
        Path(args.output).write_text(text,encoding="utf-8")
    else:
        print(text)
    return 0
if __name__=="__main__":
    sys.exit(main())
