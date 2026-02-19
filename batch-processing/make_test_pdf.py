"""One-off script to create source_pdf/feb-19.pdf for testing."""
from pathlib import Path

# Minimal valid PDF: "Sample data - Feb 19"
body = b"""%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1/MediaBox[0 0 612 792]>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>>>>>/Contents 4 0 R>>
endobj
4 0 obj
<</Length 48>>
stream
BT /F1 14 Tf 100 700 Td (Sample data - Feb 19) Tj ET

endstream
endobj
"""
# Byte offsets of "1 0 obj", "2 0 obj", "3 0 obj", "4 0 obj" in body
o1 = body.index(b"1 0 obj")
o2 = body.index(b"2 0 obj")
o3 = body.index(b"3 0 obj")
o4 = body.index(b"4 0 obj")
xref = (
    b"xref\n0 5\n"
    b"0000000000 65535 f \n"
    + f"{o1:010d} 00000 n \n".encode()
    + f"{o2:010d} 00000 n \n".encode()
    + f"{o3:010d} 00000 n \n".encode()
    + f"{o4:010d} 00000 n \n".encode()
)
startxref = len(body) + len(xref)
trailer = f"trailer\n<</Size 5/Root 1 0 R>>\nstartxref\n{startxref}\n%%EOF\n".encode()
pdf = body + xref + trailer

# Write to source_pdf in same directory as this script
base = Path(__file__).resolve().parent
out = base / "source_pdf" / "feb-20.pdf"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(pdf)
assert out.exists(), f"Failed to create {out}"
print("Created", out, len(pdf), "bytes")
