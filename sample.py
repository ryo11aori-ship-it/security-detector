import base64
import os
import sys

print("Dummy malware execution started.")

target_domain=base64.b64decode(b"aHR0cDovL21hbGljaW91cy1kb21haW4uY29tL3BheWxvYWQuZXhl")
print(target_domain)

suspicious_cmd="powershell.exe -encodedcommand ZQBjAGgAbwAgACIAaABhAGMAawBlAGQAIgA="
print(suspicious_cmd)

sys.exit(0)
