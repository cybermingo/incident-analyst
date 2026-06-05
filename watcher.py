import subprocess
from parser.log_parser import parse_and_send

def main():
    print("[*] Streaming DVWA logs (docker logs -f dvwa)...")
    try:
        process = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "0", "dvwa"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
    except Exception as e:
        print(f"[watcher] Failed to start docker logs: {e}")
        return

    for line in process.stdout:
        if line:
            parse_and_send(line)

if __name__ == "__main__":
    main()