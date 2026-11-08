import os
import sys
import subprocess
import time
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

def print_banner():
    banner = """
==========================================================================
                    WEBSENTINEL AI CYBER DEFENSE PLATFORM
              AI-Powered Web Threat Detection & Intelligence
                  Detect. Investigate. Understand. Verify.
==========================================================================
  Frontend UI : http://localhost:5173
  Backend API : http://127.0.0.1:8000
  API Docs    : http://127.0.0.1:8000/docs
==========================================================================
"""
    print(banner, flush=True)

def main():
    print_banner()

    print("[*] Starting WebSentinel AI FastAPI Backend on port 8000...", flush=True)
    python_exe = sys.executable
    backend_proc = subprocess.Popen(
        [python_exe, "run_backend.py"],
        cwd=BACKEND_DIR
    )

    time.sleep(2)

    print("[*] Starting WebSentinel AI React Frontend on port 5173...", flush=True)
    # Check if npm or npm.cmd
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=FRONTEND_DIR
    )

    print("[✓] WebSentinel AI Platform is operational! Press Ctrl+C to terminate.", flush=True)

    try:
        while True:
            time.sleep(1)
            if backend_proc.poll() is not None:
                print("[!] Backend exited unexpectedly.", flush=True)
                break
            if frontend_proc.poll() is not None:
                print("[!] Frontend exited unexpectedly.", flush=True)
                break
    except KeyboardInterrupt:
        print("\n[*] Shutting down WebSentinel AI processes...", flush=True)
    finally:
        backend_proc.terminate()
        frontend_proc.terminate()
        backend_proc.wait()
        frontend_proc.wait()
        print("[✓] WebSentinel AI stopped cleanly.", flush=True)

if __name__ == "__main__":
    main()

