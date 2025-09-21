import hashlib
import os
import json
import argparse
from datetime import datetime

# --- Hash a file ---
def hash_file(file):
    h = hashlib.sha256()
    with open(file, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

# --- Create baseline ---
def create_baseline(directory, baseline_file=r"C:\Users\dell\OneDrive\Bureau\baseline.json"):
    baseline = {}
    for root, dirs, files in os.walk(directory):
        for filename in files:
            path = os.path.normpath(os.path.join(root, filename))
            try:
                baseline[path] = {
                    "hash": hash_file(path),
                    "last_modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                }
            except Exception as e:
                print(f"Skipping {path}: {e}")

    print("Saving baseline to:", baseline_file)
    with open(baseline_file, "w") as b:
        json.dump(baseline, b, indent=4)
    print(f"Baseline saved to {baseline_file}")

# --- Log changes for Wazuh ---
def log_change(change_type, filepath, hash_value=None, log_file="fim_logs.json"):
    event = {
        "event_type": "file_change",
        "change": change_type,
        "file": filepath,
        "hash": hash_value,
        "timestamp": datetime.now().isoformat()  # use current time, not os.path.getmtime()
    }
    with open(log_file, "a") as log:
        log.write(json.dumps(event) + "\n")

# --- Check integrity and require authorization ---
def integrity_check(directory, baseline_file, log_file="fim_logs.json"):
    if not os.path.exists(baseline_file):
        print(f"[!] Baseline file not found: {baseline_file}")
        return

    # Load baseline
    with open(baseline_file, "r") as b:
        baseline = json.load(b)

    # Scan current state
    current = {}
    for root, dirs, files in os.walk(directory):
        for filename in files:
            path = os.path.normpath(os.path.join(root, filename))
            try:
                current[path] = {
                    "hash": hash_file(path),
                    "last_modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                }
            except Exception as e:
                print(f"Skipping {path}: {e}")

    # Track changes
    detected_changes = []

    # Added or modified
    for path, values in current.items():
        if path in baseline:
            if baseline[path]["hash"] != values["hash"]:
                detected_changes.append((path, "Modified", values["hash"]))
        else:
            detected_changes.append((path, "Added", values["hash"]))

    # Deleted
    for path in baseline:
        if path not in current:
            detected_changes.append((path, "Deleted", None))

    # Handle detected changes
    for path, change_type, hash_value in detected_changes:
        print(f"[{change_type}] {path}")
        authorized = input("Is this change authorized? (y/n): ").lower() == 'y'

        log_change(change_type, path, hash_value, log_file)

        if authorized:
            if change_type == "Deleted":
                baseline.pop(path, None)
            else:  # Added or Modified
                baseline[path] = {
                    "hash": hash_value,
                    "last_modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                }
        else:
            print(f"[!] Unauthorized change logged: {path}")

    # Save updated baseline
    if detected_changes:
        with open(baseline_file, "w") as b:
            json.dump(baseline, b, indent=4)
        print("[+] Baseline updated with authorized changes.")
    else:
        print("No integrity issues detected.")

# --- Main program ---
def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitoring (FIM)")
    parser.add_argument("mode", choices=["init", "check"], help="Choose 'init' to create baseline or 'check' to verify integrity")
    parser.add_argument("folder", help="Folder to monitor")
    parser.add_argument("--baseline", default=r"C:\Users\dell\OneDrive\Bureau\baseline.json", help="Path to baseline JSON file")
    parser.add_argument("--logfile", default=r"C:\Users\dell\OneDrive\Bureau\fim_logs.json", help="Path to JSON log file for Wazuh")

    args = parser.parse_args()
    folder = os.path.normpath(args.folder)

    if not os.path.isdir(folder):
        print(f"[!] Error: Folder does not exist -> {folder}")
        return

    if args.mode == "init":
        create_baseline(folder, args.baseline)
    elif args.mode == "check":
        integrity_check(folder, args.baseline, args.logfile)

if __name__ == "__main__":
    main()
