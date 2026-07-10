#!/usr/bin/env python3
# Usage: python3 check_xlsx.py <file.xlsx>  -> reports any formula cells per sheet
import sys, zipfile
f = sys.argv[1]
z = zipfile.ZipFile(f)
hits = {n: z.read(n).count(b"<f>") for n in z.namelist()
        if n.startswith("xl/worksheets/") and n.endswith(".xml") and b"<f>" in z.read(n)}
print("FORMULA CELLS FOUND:", hits if hits else "none — file is clean ✔")
