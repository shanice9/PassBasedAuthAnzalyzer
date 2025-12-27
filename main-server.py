import sqlite3
import hashlib
import secrets
import uvicorn
from enum import Enum
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import bcrypt
from argon2 import PasswordHasher

# sqlite db filename
DB_NAME = "PassBasedAuth.sqlite"

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
    algo: HashAlgo = HashAlgo.SHA256
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

@app.post("/register")
def register(request: RegisterRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    cursor = conn.cursor()

    if user_exists(request.username, cursor):
        raise HTTPException(status_code=400, detail="Username already exists")

    # hash the password
    hash_data = get_password_hash(request.password, request.algo)

    # saving to the DB
    try:
        insert_user_to_db(request.username, request.algo, hash_data["salt"], hash_data["hash"], request.totp_secret, cursor, conn)
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": "User created successfully",
        "username": request.username,
        "algo_used": request.algo,
        "totp_secret": request.totp_secret
    }


@app.post("/login")
def login(request: LoginRequest, conn: sqlite3.Connection = Depends(get_db_conn)):
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
    user = cursor.fetchone()

    if not user or not verify_password(request.password, user):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user_id": user["id"],
        "username": user["username"]
    }


if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)
