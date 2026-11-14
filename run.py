import os
import sys
import subprocess
import webbrowser
import threading
import time

# Auto-detect and fix missing dependencies or wrong python interpreter
try:
    import uvicorn
    import fastapi
    import httpx
    import pydantic
except ImportError:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(base_dir, "venv", "Scripts", "python.exe")
    
    # If a local venv exists and current python is not the venv python, re-execute with venv
    if os.path.exists(venv_python) and os.path.normcase(sys.executable) != os.path.normcase(venv_python):
        print(f"[*] Chuyen tiep qua trinh thuc thi sang moi truong venv: {venv_python}")
        ret = subprocess.call([venv_python, os.path.abspath(__file__)] + sys.argv[1:])
        sys.exit(ret)
    else:
        # Otherwise attempt auto-installation
        print("[*] Dang tu dong cai dat cac thu vien con thieu tu requirements.txt...")
        req_file = os.path.join(base_dir, "requirements.txt")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
            import uvicorn
        except Exception as e:
            print(f"[!] Loi: Khong the tu dong cai dat uvicorn: {e}")
            print(f"[!] Vui long chay: {sys.executable} -m pip install -r requirements.txt")
            input("Nhan Enter de thoat...")
            sys.exit(1)

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("=" * 65)
    print("  AEGISWEB - WEB SECURITY SCANNER & METASPLOIT ADVISORY APP")
    print("=" * 65)
    print("[*] Khoi chay local server tai: http://127.0.0.1:8000")
    print("[*] Dang tu dong mo trinh duyet...")
    print("[*] Nhan Ctrl+C de dung server.\n")

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
