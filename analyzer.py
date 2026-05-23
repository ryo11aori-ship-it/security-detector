import os
import math
import hashlib
import json
import logging
import magic
import yara
import pefile

class StaticCoreAnalyzer:
    def __init__(self):
        self.magic_handle=magic.Magic(mime=True)
    def calculate_hashes(self,file_path):
        h_md5=hashlib.md5()
        h_sha1=hashlib.sha1()
        h_sha256=hashlib.sha256()
        with open(file_path,'rb') as f:
            c=f.read()
            h_md5.update(c)
            h_sha1.update(c)
            h_sha256.update(c)
        return {"md5":h_md5.hexdigest(),"sha1":h_sha1.hexdigest(),"sha256":h_sha256.hexdigest()}
    def calculate_entropy(self,file_path):
        with open(file_path,'rb') as f:
            data=f.read()
        if not data:
            return 0.0
        entropy=0.0
        data_len=len(data)
        byte_counts=[0]*256
        for byte in data:
            byte_counts[byte]+=1
        for count in byte_counts:
            if count>0:
                probability=float(count)/data_len
                entropy-=probability*math.log2(probability)
        return entropy
    def analyze_core(self,file_path):
        if not os.path.exists(file_path):
            return {"error":"File not found"}
        return {"mime_type":self.magic_handle.from_file(file_path),"hashes":self.calculate_hashes(file_path),"entropy":self.calculate_entropy(file_path)}

class LocalYaraScanner:
    def __init__(self,rule_target):
        self.rule_target=rule_target
        self.rules=self.compile_rules()
    def compile_rules(self):
        if not os.path.exists(self.rule_target):
            return None
        if os.path.isfile(self.rule_target):
            return yara.compile(filepath=self.rule_target)
        rule_dict={}
        for root,dirs,files in os.walk(self.rule_target):
            for f_name in files:
                if f_name.endswith((".yar",".yara")):
                    rule_dict[f_name]=os.path.join(root,f_name)
        if not rule_dict:
            return None
        return yara.compile(filepaths=rule_dict)
    def scan_file(self,target_file):
        if not self.rules:
            return {"error":"Rules not loaded"}
        if not os.path.exists(target_file):
            return {"error":"Target file not found"}
        try:
            matches=self.rules.match(target_file)
            match_list=[]
            for match in matches:
                match_list.append(match.rule)
            return {"yara_matches":match_list}
        except Exception as e:
            return {"error":str(e)}

class LocalPEAnalyzer:
    def __init__(self):
        pass
    def analyze_pe(self,file_path):
        if not os.path.exists(file_path):
            return {"error":"File not found"}
        try:
            pe=pefile.PE(file_path)
        except Exception as e:
            return {"error":str(e)}
        result={"entry_point":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),"image_base":hex(pe.OPTIONAL_HEADER.ImageBase),"imports":{}}
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name=entry.dll.decode('utf-8','ignore') if entry.dll else "unknown"
                funcs=[]
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8','ignore'))
                result["imports"][dll_name]=funcs
        return result

class LocalMalwareAnalyzer:
    def __init__(self,yara_rules_path):
        self.yara_rules_path=yara_rules_path
        self.logger=self.setup_logger()
        self.core_analyzer=StaticCoreAnalyzer()
        self.yara_scanner=LocalYaraScanner(yara_rules_path)
        self.pe_analyzer=LocalPEAnalyzer()
    def setup_logger(self):
        logger=logging.getLogger("Analyzer")
        logger.setLevel(logging.INFO)
        return logger
    def run_static_analysis(self,file_path):
        self.logger.info("Static analysis started.")
        core_info=self.core_analyzer.analyze_core(file_path)
        yara_info=self.yara_scanner.scan_file(file_path)
        static_report={"core":core_info,"yara":yara_info}
        if "error" not in core_info and "pe" in core_info.get("mime_type","").lower():
            static_report["pe_info"]=self.pe_analyzer.analyze_pe(file_path)
        return static_report
    def analyze_sample(self,file_path):
        if not os.path.exists(file_path):
            return json.dumps({"error":"File not found"})
        static_result=self.run_static_analysis(file_path)
        final_report={"file_path":file_path,"static_analysis":static_result}
        return json.dumps(final_report,indent=4)

if __name__=="__main__":
    pass
    # テスト実行用のコード
    # yara_dir="./yara_rules"
    # os.makedirs(yara_dir,exist_ok=True)
    # analyzer=LocalMalwareAnalyzer(yara_dir)
    # print(analyzer.analyze_sample("sample.exe"))
