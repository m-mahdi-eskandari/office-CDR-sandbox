# Office CDR Sandbox

A security tool for sanitizing Microsoft Office documents and executing them in an isolated VirtualBox sandbox.  
The goal is to remove common malicious content (macros, external URLs) before opening files, and to ensure suspicious files are only opened inside a safe VM.

---

## Features

- 🔍 VirusTotal integration  
  - Computes file SHA256 and checks against VirusTotal database.  
  - If the file is flagged as *malicious*, execution stops immediately.  

- 🧹 Content Disarm & Reconstruction (CDR)  
  - Removes vbaProject.bin (macros).  
  - Replaces all external http:// and https:// links with 0.0.0.0.  
  - Creates a safe_<filename> version of the document.  
  - Works with both modern Office formats (.docx, .xlsx, .pptx, etc.) and legacy formats (.doc, .xls, .ppt) via LibreOffice conversion.  

- 🖥 VirtualBox sandbox execution  
  - The sanitized file is copied to a host share folder.  
  - Opened inside a VM via VBoxManage guestcontrol.  
  - Helps analyze suspicious documents in a safe, isolated environment.

---

## Requirements

- Python 3.8+
- Libraries:

      pip install requests colorama

---

LibreOffice (for cleaning legacy .doc, .xls, .ppt files)
VirtualBox with Guest Additions installed

A configured VM:
  - Windows with Microsoft Office installed
  - No Internet connection inside VM (air-gapped)
  - Shared folder between host and guest (C:\Users\Public\share on host → Z:\ inside VM)

---

## Usage

    python office_cdr_sandbox.py <office_file>

---

## Workflow

The script checks the file hash on VirusTotal.

If flagged → ❌ printed in red and script exits.

If clean → performs CDR sanitization and creates a safe copy.

The safe file is copied to host share and executed inside VirtualBox VM.

---

## Notes

The VT_API_KEY in the script must be replaced with your own VirusTotal API key.

If LibreOffice is not installed, cleaning legacy files (.doc, .xls, .ppt) will not work.

This project is for research and security analysis only. Use responsibly.

---

### Example Output

    [CDR][modern] cleaned -> safe_example.docx, removed: ['vbaProject.bin', 'urls in word/_rels/document.xml.rels']
    [CDR] Safe file created: safe_example.docx
    ------- start VirtualBox sandbox --------
    Copied file to host share: C:\Users\Public\share\safe_example.docx
    ------- Finish --------
