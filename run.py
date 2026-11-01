import os
import sys
import time
import socket
import webbrowser
import threading

if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def is_port_in_use(port: int, host: str = '127.0.0.1') -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def open_browser(url: str, delay: float = 1.2):
    time.sleep(delay)
    print(f"\n[+] Launching Galvan Omnitrix Interface: {url}")
    webbrowser.open(url)

def main():
    PORT = int(os.environ.get("PORT", 5001))
    HOST = '127.0.0.1'
    URL = f"http://{HOST}:{PORT}"

    print("=" * 72)
    print("   [+] CAEMP // OMNITRIX EDITION — UNIFIED CYBERSECURITY PLATFORM")
    print("   [+] Integrated: CAEMP Exposure Monitoring + PhishGuard URL Scanner")
    print("   [+] Aesthetic : Galvan Level-20 Technology Omnitrix Hardware Interface")
    print("=" * 72)

    if is_port_in_use(PORT, HOST):
        print(f"[*] Omnitrix server is already active on {URL}!")
        print("[*] Launching browser...")
        webbrowser.open(URL)
        return

    print(f"[*] Starting unified server on {URL}...")
    threading.Thread(target=open_browser, args=(URL, 1.2), daemon=True).start()

    from app import app
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
