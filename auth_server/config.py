import json
import os
from enum import Enum

DB_NAME = "PassBasedAuth.sqlite"
LOG_FILE = "attempts.log"
USERS_FILE = "users.json"
CONFIG_FILE = "config.json"

# Default values
HASH_ALGO = "sha256"
GROUP_SEED = "534919433"
PROTECTION_FLAGS = []
PEPPER_SECRET = ""
RATE_LIMIT = "3/minute"
CAPTCHA_THRESHOLD = 10
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_SECS = 60

# all possible hashes
class HashAlgo(str, Enum):
    SHA256 = "sha256"
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"


def load_config():
    global HASH_ALGO, PROTECTION_FLAGS, PEPPER_SECRET, RATE_LIMIT, CAPTCHA_THRESHOLD, LOCKOUT_THRESHOLD, LOCKOUT_DURATION_SECS
    if not os.path.exists(CONFIG_FILE):
        print(f"{CONFIG_FILE} not found, stopping server.")
        raise FileNotFoundError(f"{CONFIG_FILE} not found")

    valid_algos = set(item.value for item in HashAlgo)
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "algo_type" in data and data["algo_type"].lower() in valid_algos:
                HASH_ALGO = data["algo_type"].lower()
            else:
                HASH_ALGO = HashAlgo.SHA256
                print(f"Defaulting algo => {HASH_ALGO}.")

            PROTECTION_FLAGS = data.get("protection_flags", [])
            PEPPER_SECRET = os.getenv("SERVER_PEPPER", "")
            RATE_LIMIT = data.get("rate_limit", "3/minute")
            CAPTCHA_THRESHOLD = data.get("captcha_threshold", 10)
            LOCKOUT_THRESHOLD = data.get("lockout_threshold", 3)
            LOCKOUT_DURATION_SECS = data.get("lockout_duration", 60)
    except Exception as e:
        print(f"Error loading {CONFIG_FILE}: {e}")


def load_group_seed():
    global GROUP_SEED
    if not os.path.exists(USERS_FILE):
        print(f"{USERS_FILE} not found, using default seed.")
        return

    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "group_seed" in data:
                GROUP_SEED = data["group_seed"]
                print(f"Loaded GROUP_SEED: {GROUP_SEED}")
    except Exception as e:
        print(f"Error loading seed from {USERS_FILE}: {e}")
