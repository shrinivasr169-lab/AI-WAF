import base64
import re
import zlib

data = open("../AI_Powered_WAF_Project_Requirements.pdf", "rb").read()
out = []
for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
    raw = m.group(1).strip()
    if raw.endswith(b"~>"):
        raw = raw[:-2]
    try:
        decoded = base64.a85decode(raw, adobe=False)
        out.append(zlib.decompress(decoded))
    except Exception:
        continue

text = b"\n".join(out).decode("latin-1")
parts = re.findall(r"\(((?:[^()\\]|\\.)*)\)", text)
for p in parts:
    line = p.replace("\\(", "(").replace("\\)", ")").replace("\\n", "\n")
    print(line)
