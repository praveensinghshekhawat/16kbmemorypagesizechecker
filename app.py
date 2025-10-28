from flask import Flask, request, jsonify, render_template
import os, tempfile, zipfile, shutil, subprocess
from elftools.elf.elffile import ELFFile
from io import BytesIO

app = Flask(__name__)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
PAGE = 16384  # 16KB

def check_zipalign(apk_path):
    try:
        out = subprocess.run(["zipalign", "-c", "-v", str(PAGE), apk_path],
                             capture_output=True, text=True, timeout=15)
        return {
            "available": True,
            "returncode": out.returncode,
            "stdout": out.stdout,
            "stderr": out.stderr
        }
    except FileNotFoundError:
        return {"available": False, "error": "zipalign not found"}

def check_so_alignment(so_bytes):
    buf = BytesIO(so_bytes)
    elffile = ELFFile(buf)
    issues = []
    for seg in elffile.iter_segments():
        ph = seg.header
        if ph['p_type'] == 'PT_LOAD':
            p_align = ph['p_align']
            p_offset = ph['p_offset']
            p_vaddr = ph['p_vaddr']
            ok = False
            if isinstance(p_align, int) and p_align >= PAGE:
                ok = True
            if (p_offset % PAGE == 0) and (p_vaddr % PAGE == 0):
                ok = True
            if not ok:
                issues.append({
                    "p_align": p_align,
                    "p_offset": p_offset,
                    "p_vaddr": p_vaddr
                })
    return issues

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_apk():
    f = request.files.get("apk")
    if not f or not f.filename.endswith(".apk"):
        return jsonify({"error": "Invalid or missing APK"}), 400

    tmpdir = tempfile.mkdtemp(dir=UPLOAD_DIR)
    apk_path = os.path.join(tmpdir, f.filename)
    f.save(apk_path)

    report = {"zipalign": None, "so_checks": [], "summary": {}}

    # Check zipalign
    #report["zipalign"] = check_zipalign(apk_path)

    # Extract and check .so files
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            so_files = [n for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")]
            for so_name in so_files:
                so_bytes = z.read(so_name)
                issues = check_so_alignment(so_bytes)
                report["so_checks"].append({"so": so_name, "issues": issues})
    except zipfile.BadZipFile:
        report["error"] = "Invalid APK file"

    bad_so = [s for s in report["so_checks"] if s["issues"]]
    ok_zip = (report["zipalign"].get("available") and report["zipalign"].get("returncode")==0) if report["zipalign"] else None
    # report["summary"]["zipalign_ok"] = ok_zip
    report["summary"]["so_ok"] = (len(bad_so) == 0)
    #report["summary"]["overall_ok"] = (ok_zip is not False) and (len(bad_so) == 0)

    # Print message based on SO alignment result
    if report["summary"]["so_ok"]:
        report["summary"]["RESULT"] = "✅ 16KB Page Compliant"
    else:
        report["summary"]["RESULT"] = "❌ Not 16KB Compliant"

    shutil.rmtree(tmpdir, ignore_errors=True)
    return jsonify(report)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
