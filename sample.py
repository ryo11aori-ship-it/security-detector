import os

target_file="sample.exe"

with open(target_file,"wb") as f:
    f.write(b"MZ")
    f.write(b"\x00"*60)
    f.write(b"PE\x00\x00")
    f.write(b"\x00"*20)
    f.write(os.urandom(4096))
    f.write(b"powershell.exe -encodedcommand ")
    f.write(b"VirtualAlloc ")
    f.write(b"http://malicious-dummy-domain.com/payload.exe ")
    f.write(b"cmd.exe /c ")
    f.write(b"RunOnce ")

print("Dummy malware sample generated: sample.exe")
