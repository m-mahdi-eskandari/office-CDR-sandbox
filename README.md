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
