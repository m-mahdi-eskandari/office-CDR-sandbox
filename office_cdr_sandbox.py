import os
import sys
import zipfile
import shutil
import tempfile
import subprocess
import hashlib
import requests
import xml.etree.ElementTree as ET
from colorama import Fore, Style

# ================== Configuration ==================
# VirusTotal
VT_API_KEY = "YOUR_API_KEY_HERE"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Office supported extensions
MODERN_EXTS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
LEGACY_EXTS = {".doc", ".xls", ".ppt"}

# VirtualBox sandbox config
VM_NAME = "OfficeSandbox"
VM_USER = "VM_USERNAME"
VM_PASSWORD = "VM_PASSWORD"
HOST_SHARE = "C:\\Users\\Public\\share"
GUEST_SHARE = "Z:\\"

# ================== VirusTotal Check ==================
def virustotal_check(file_path):
    """Check file hash against VirusTotal."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()

        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(VT_URL + digest, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) > 0
    except Exception as e:
        print(f"[!] VirusTotal error for {file_path}: {e}")
    return False

# ================== File Type Check ==================
def is_modern(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    return ext in MODERN_EXTS

def is_legacy(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    return ext in LEGACY_EXTS

# ================== Modern CDR ==================
def replace_urls_in_xml(xml_file):
    """Replace external HTTP/HTTPS URLs in .rels XML files with 0.0.0.0."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    ns = {'rel': 'http://schemas.openxmlformats.org/package/2006/relationships'}
    changed = False

    for rel in root.findall('rel:Relationship', ns):
        target = rel.get('Target')
        if target and target.startswith(('http://', 'https://')):
            rel.set('Target', '0.0.0.0')
            changed = True

    if changed:
        tree.write(xml_file, encoding="UTF-8", xml_declaration=True)
    return changed

def clean_modern(file_path):
    """Clean modern Office files: remove macros and external links."""
    safe_name = "safe_" + os.path.basename(file_path)
    safe_path = os.path.join(os.path.dirname(file_path), safe_name)
    temp_dir = tempfile.mkdtemp()
    removed = []

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            z.extractall(temp_dir)

        for root, _, files in os.walk(temp_dir):
            for fname in files:
                if fname.lower() == "vbaproject.bin":
                    os.remove(os.path.join(root, fname))
                    removed.append("vbaProject.bin")

        for root_dir, _, files in os.walk(temp_dir):
            for fname in files:
                if fname.endswith(".rels"):
                    fpath = os.path.join(root_dir, fname)
                    if replace_urls_in_xml(fpath):
                        removed.append(f"urls in {os.path.relpath(fpath,temp_dir)}")

        with zipfile.ZipFile(safe_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root_dir, _, files in os.walk(temp_dir):
                for fname in files:
                    full = os.path.join(root_dir, fname)
                    arcname = os.path.relpath(full, temp_dir)
                    zipf.write(full, arcname)

        print(f"[CDR][modern] cleaned -> {safe_path}, removed: {removed if removed else 'None'}")
        return safe_path

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ================== Legacy CDR ==================
def libreoffice_available():
    try:
        subprocess.run(["soffice.com", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def clean_legacy(file_path):
    """Clean legacy Office files by converting them via LibreOffice."""
    if not libreoffice_available():
        print("[CDR][legacy] LibreOffice not available. Cannot clean legacy file safely.")
        return None

    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run([
            "soffice.com", "--headless",
            "--convert-to", "docx",
            "--outdir", temp_dir,
            file_path
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        converted_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(file_path))[0]+".docx")
        if not os.path.exists(converted_file):
            return None

        unzip_dir = os.path.join(temp_dir, "unzipped")
        os.makedirs(unzip_dir, exist_ok=True)
        with zipfile.ZipFile(converted_file, "r") as z:
            z.extractall(unzip_dir)

        for root_dir, _, files in os.walk(unzip_dir):
            for fname in files:
                if fname.endswith(".rels"):
                    fpath = os.path.join(root_dir, fname)
                    replace_urls_in_xml(fpath)

        safe_name = "safe_" + os.path.basename(file_path)
        safe_path = os.path.join(os.path.dirname(file_path), safe_name)
        with zipfile.ZipFile(safe_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root_dir, _, files in os.walk(unzip_dir):
                for fname in files:
                    full = os.path.join(root_dir, fname)
                    arcname = os.path.relpath(full, unzip_dir)
                    zipf.write(full, arcname)

        print(f"[CDR][legacy] cleaned -> {safe_path} (links replaced)")
        return safe_path

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ================== VirtualBox Sandbox ==================
def sandbox(file_path):
    os.makedirs(HOST_SHARE, exist_ok=True)
    file_name = os.path.basename(file_path)
    host_file_path = os.path.join(HOST_SHARE, file_name)
    shutil.copy(file_path, host_file_path)
    print(f"Copied file to host share: {host_file_path}")

    guest_file_path = os.path.join(GUEST_SHARE, file_name)

    subprocess.run([
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        "guestcontrol", VM_NAME, "run",
        "--username", VM_USER,
        "--password", VM_PASSWORD,
        "--exe", r"C:\Program Files\Microsoft Office\Office15\WINWORD.EXE",
        "--", guest_file_path
    ], check=True)

# ================== Main ==================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python office_cdr_sandbox.py <office-file>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print("File not found:", file_path)
        sys.exit(1)

    # ---------- VirusTotal ----------
    if virustotal_check(file_path):
        print(Fore.RED + f"[!] File flagged by VirusTotal: {file_path}" + Style.RESET_ALL)
        sys.exit(1)

    # ---------- Cleaning ----------
    safe_path = None
    if is_modern(file_path):
        safe_path = clean_modern(file_path)
    elif is_legacy(file_path):
        safe_path = clean_legacy(file_path)
    else:
        print("Unsupported file type.")
        sys.exit(1)

    if safe_path:
        print(f"[CDR] Safe file created: {safe_path}")
    else:
        print("[CDR] Cleaning failed.")
        sys.exit(1)

    print(Fore.GREEN + '------- start VirtualBox sandbox --------' + Style.RESET_ALL)
    sandbox(safe_path)
    print(Fore.LIGHTYELLOW_EX + '------- Finish --------' + Style.RESET_ALL)
