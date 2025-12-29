import sqlite3
import hashlib
import secrets
import uvicorn
import json
import os
import bcrypt
import time
from enum import Enum
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from argon2 import PasswordHasher

# sqlite db filename
DB_NAME = "PassBasedAuth.sqlite"
LOG_FILE = "attempts.log"
USERS_FILE = "users.json"
CONFIG_FILE = "config.json"
HASH_ALGO = "sha256"
GROUP_SEED = "534919433"
PROTECTION_FLAGS = []
PEPPER_SECRET = ""

# argon2id setup
ph_argon2 = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

app = FastAPI(title="Auth Server")
# all possible hashes
class HashAlgo(str, Enum):
    SHA256 = "sha256"
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"

class RegisterRequest(BaseModel):
    username: str
    password: str
    totp_secret: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

# initializing db
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        algo_type TEXT NOT NULL,
        salt TEXT, 
        password_hash TEXT NOT NULL,
        totp_secret TEXT
    )
    ''')
    conn.commit()
    conn.close()


def load_users():
    if not os.path.exists(USERS_FILE):
        print(f"{USERS_FILE} not found, no users loaded.")
        return

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            users_list = data.get("users", [])
            count = 0

            for user in users_list:
                username = user["username"]
                plain_password = user["password"]
                # Using get in case totp_secret doesn't exists
                totp_secret = user.get("totp_secret")

                reg_req = RegisterRequest(
                    username=username,
                    password=plain_password,
                    totp_secret=totp_secret
                )

                try:
                    register(reg_req, conn)
                    count += 1
                except HTTPException as e:
                    print(f"Skipping user '{username}': {e.detail}")
                except Exception as e:
                    print(f"Error registering '{username}': {e}")
            print(f"Successfully loaded {count} new users into the database.")

    except Exception as e:
        print(f"Error loading users from {USERS_FILE}: {e}")
    finally:
        conn.close()


def load_config():
    global HASH_ALGO, PROTECTION_FLAGS, PEPPER_SECRET
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
                print(f"'algo_type' key not found in {CONFIG_FILE}, setting default algo => {HASH_ALGO}.")
            PROTECTION_FLAGS = data.get("protection_flags", [])
            if "pepper" in PROTECTION_FLAGS:
                PEPPER_SECRET = os.getenv("SERVER_PEPPER", "")
                if PEPPER_SECRET:
                    print(f"Pepper loaded from environment variable.")
                else:
                    print("WARNING: 'pepper' flag is on, but SERVER_PEPPER env var is empty/missing!")
            else:
                PEPPER_SECRET = ""
    except Exception as e:
        print(f"Error loading {CONFIG_FILE}: {e}")
    return


def load_group_seed():
    global GROUP_SEED
    if not os.path.exists(USERS_FILE):
        print(f"{USERS_FILE} not found, Using default seed => {GROUP_SEED}.")
        return

    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "group_seed" in data:
                GROUP_SEED = data["group_seed"]
                print(f"Loaded GROUP_SEED from {USERS_FILE}: {GROUP_SEED}")
            else:
                print(f"'group_seed' key not found in users.json, setting default seed => {GROUP_SEED}.")
    except Exception as e:
        print(f"Error loading {USERS_FILE}: {e}")


def get_db_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def user_exists(username: str, cursor: sqlite3.Cursor) -> bool:
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        return True
    return False


def verify_password(plain_password: str, user_row: sqlite3.Row) -> bool:
    if PEPPER_SECRET:
        plain_password = plain_password + PEPPER_SECRET

    algo = user_row["algo_type"]
    stored_hash = user_row["password_hash"]
    password_bytes = plain_password.encode('utf-8')

    if algo == HashAlgo.SHA256:
        salt = user_row["salt"]
        combined = salt + plain_password
        check_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return check_hash == stored_hash

    elif algo == HashAlgo.BCRYPT:
        stored_hash_bytes = stored_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)

    elif algo == HashAlgo.ARGON2:
        try:
            return ph_argon2.verify(stored_hash, plain_password)
        except Exception:
            return False

    return False


def get_password_hash(password: str, algo: str) -> dict:
    if PEPPER_SECRET:
        password = password + PEPPER_SECRET
    result = {"algo": algo, "salt": None, "hash": None}
    password_bytes = password.encode('utf-8')

    if algo == HashAlgo.SHA256:
        # creating salt
        salt = secrets.token_hex(16)
        combined = salt + password
        hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()

        result["salt"] = salt
        result["hash"] = hashed

    elif algo == HashAlgo.BCRYPT:
        # creating salt
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)

        result["hash"] = hashed_bytes.decode('utf-8')
        # no need to set salt because it's in the hash

    elif algo == HashAlgo.ARGON2:
        # salt is automated in argon2 lib
        hashed = ph_argon2.hash(password)

        result["hash"] = hashed
        # no need to set salt because it's in the hash

    return result


def insert_user_to_db(username: str, algo: HashAlgo, salt: Optional[str], hash: str, totp_secret: str, cursor: sqlite3.Cursor, conn: sqlite3.Connection):
    try:
        cursor.execute('''
            INSERT INTO users (username, algo_type, salt, password_hash, totp_secret)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            username,
            algo,
            salt,
            hash,
            totp_secret
        ))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=str(e))


def log_attempt(username: str, hash_mode: str, result: str, latency_ms: float, protection_flags: str):
    log_entry = {
        "timestamp": time.time(),
        "group_seed": GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": latency_ms
    }
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")


@app.post("/register")
def register(request: RegisterRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    cursor = conn.cursor()

    if user_exists(request.username, cursor):
        raise HTTPException(status_code=400, detail="Username already exists")

    # hash the password
    hash_data = get_password_hash(request.password, HASH_ALGO)

    # saving to the DB
    try:
        insert_user_to_db(request.username, HASH_ALGO, hash_data["salt"], hash_data["hash"], request.totp_secret, cursor, conn)
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": "User created successfully",
        "username": request.username,
        "totp_secret": request.totp_secret
    }


@app.post("/login")
def login(request: LoginRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    start_time = time.time()
    hash_mode = "Unknown"
    login_success = False
    cursor = conn.cursor()

    # Check that user exists and fetch the data for login
    cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
    user = cursor.fetchone()

    # Check user exists
    if user:
        hash_mode = user["algo_type"]
        # Check password is correct
        if verify_password(request.password, user):
            login_success = True

    # Setting log parameters
    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    result_str = "Login successful" if login_success else "Invalid credentials"

    log_attempt(request.username, hash_mode, result_str, latency_ms, PROTECTION_FLAGS)

    if not login_success:
        raise HTTPException(status_code=401, detail=result_str)

    return {
        "message": result_str,
        "user_id": user["id"],
        "username": user["username"]
    }


if __name__ == "__main__":
    load_config()
    load_group_seed()
    init_db()
    load_users()
    uvicorn.run(app, host="0.0.0.0", port=8000)
