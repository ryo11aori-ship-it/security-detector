#!/usr/bin/env python3
import argparse
import json
import math
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
try:
    import numpy as np
except Exception:
    np=None
try:
    import onnxruntime as ort
except Exception:
    ort=None
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
class LocalMalConvEngine:
    def __init__(self,model_path:str):
        self.model_path=model_path
        self.session=None
        self.max_len=2*1024*1024
    def load(self)->bool:
        if not ort or not np or not self.model_path or not os.path.exists(self.model_path):
            return False
        try:
            self.session=ort.InferenceSession(self.model_path,providers=['CPUExecutionProvider'])
            return True
        except Exception:
            return False
    def predict(self,file_path:str)->Dict[str,Any]:
        if not self.session:
            return {"available":False,"error":"MalConv model not loaded or missing dependencies (onnxruntime/numpy)"}
        try:
            with open(file_path,"rb") as f:
                data=f.read(self.max_len)
            input_data=np.frombuffer(data,dtype=np.uint8).astype(np.int64)
            if len(input_data)<self.max_len:
                input_data=np.pad(input_data,(0,self.max_len-len(input_data)),'constant')
            input_data=np.expand_dims(input_data,axis=0)
            input_name=self.session.get_inputs()[0].name
            outputs=self.session.run(None,{input_name:input_data})
            logit=outputs[0][0][0]
            probability=1.0/(1.0+math.exp(-logit))
            return {"available":True,"malconv_risk_score":int(round(probability*100)),"risk_probability":round(probability,4)}
        except Exception as e:
            return {"available":False,"error":str(e)}
class RiskFusion:
    def fuse(self,report:Dict[str,Any],rf_result:Dict[str,Any],mc_result:Dict[str,Any])->Dict[str,Any]:
        heuristic=int(report.get("risk",{}).get("risk_score",0))
        rf_avail=rf_result.get("available",False)
        mc_avail=mc_result.get("available",False)
        rf_score=int(rf_result.get("ai_risk_score",0))
        mc_score=int(mc_result.get("malconv_risk_score",0))
        if rf_avail and mc_avail:
            final_score=round((heuristic*0.4)+(rf_score*0.2)+(mc_score*0.4))
            policy="40% Heuristic + 20% RF AI + 40% MalConv DL"
        elif rf_avail:
            final_score=round((heuristic*0.5)+(rf_score*0.5))
            policy="50% Heuristic + 50% RF AI"
        elif mc_avail:
            final_score=round((heuristic*0.5)+(mc_score*0.5))
            policy="50% Heuristic + 50% MalConv DL"
        else:
            final_score=heuristic
            policy="100% Heuristic (AI unavailable)"
        yara_matches=report.get("yara",{}).get("matches",[])
        if yara_matches:
            final_score=max(final_score,75)
        final_score=max(0,min(100,final_score))
        return {"final_risk_score":final_score,"source":"multi_layer_fusion","heuristic_score":heuristic,"rf_score":rf_score if rf_avail else None,"malconv_score":mc_score if mc_avail else None,"verdict":self.verdict(final_score),"fusion_policy":policy}
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
    parser.add_argument("--malconv",default="malconv.onnx")
    parser.add_argument("--output",default=None)
    args=parser.parse_args()
    if not os.path.exists(args.report):
        print(json.dumps({"error":f"report not found: {args.report}"}))
        return 1
    with open(args.report,"r",encoding="utf-8") as f:
        report=json.load(f)
    extractor=KaggleFeatureExtractor()
    vector=extractor.extract(args.target)
    rf_engine=LocalAIEngine(args.model)
    rf_engine.load(extractor.feature_names)
    rf_prediction=rf_engine.predict(vector)
    mc_engine=LocalMalConvEngine(args.malconv)
    mc_engine.load()
    mc_prediction=mc_engine.predict(args.target)
    fusion=RiskFusion().fuse(report,rf_prediction,mc_prediction)
    output={"engine":{"name":"Offline Multi-Layer AI Engine","version":"5.0.0","mode":"fusion_inference"},"rf_prediction":rf_prediction,"malconv_prediction":mc_prediction,"fusion":fusion,"features":extractor.vector_as_dict(vector)}
    text=json.dumps(output,ensure_ascii=False,indent=2)
    if args.output:
        Path(args.output).write_text(text,encoding="utf-8")
    else:
        print(text)
    return 0
if __name__=="__main__":
    sys.exit(main())
