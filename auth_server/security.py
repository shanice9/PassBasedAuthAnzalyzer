import hashlib
import secrets
import bcrypt
from argon2 import PasswordHasher
import config
import database
import uuid
import pyotp
import time
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# argon2id setup
ph_argon2 = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

# '<ip>': <number_of_failed_attempts>
IP_FAILED_ATTEMPTS = dict()
VALID_CAPTCHA_TOKENS = set()
# '<username>': <number_of_failed_attempts>
USER_FAILED_ATTEMPTS = dict()
# '<username': <timestamp_when_unlocks>
LOCKED_USERS = dict()

def record_failed_login(username: str):
    if "account_lockout" not in config.PROTECTION_FLAGS:
        return
    current_fails = USER_FAILED_ATTEMPTS.get(username, 0) + 1
    USER_FAILED_ATTEMPTS[username] = current_fails
    if current_fails >= config.LOCKOUT_THRESHOLD:
        LOCKED_USERS[username] = time.time() + config.LOCKOUT_DURATION_SECS

def record_failed_attempt(ip: str):
    IP_FAILED_ATTEMPTS[ip] = IP_FAILED_ATTEMPTS.get(ip, 0) + 1

def reset_failed_login(username: str):
    if username in USER_FAILED_ATTEMPTS:
        del USER_FAILED_ATTEMPTS[username]
    if username in LOCKED_USERS:
        del LOCKED_USERS[username]

def reset_failed_attempts(ip: str):
    if ip in IP_FAILED_ATTEMPTS:
        del IP_FAILED_ATTEMPTS[ip]

def is_captcha_required(ip: str) -> bool:
    if "captcha" not in config.PROTECTION_FLAGS:
        return False
    return IP_FAILED_ATTEMPTS.get(ip, 0) >= config.CAPTCHA_THRESHOLD

def is_account_locked(username: str) -> bool:
    if "account_lockout" not in config.PROTECTION_FLAGS:
        return False

    if username in LOCKED_USERS:
        unlock_time = LOCKED_USERS[username]
        if time.time() < unlock_time:
            return True
        else:
            del LOCKED_USERS[username]
            if username in USER_FAILED_ATTEMPTS:
                del USER_FAILED_ATTEMPTS[username]
            return False
    return False

def generate_captcha_token() -> str:
    token = str(uuid.uuid4())
    VALID_CAPTCHA_TOKENS.add(token)
    return token

def validate_and_consume_captcha_token(token: str) -> bool:
    if token in VALID_CAPTCHA_TOKENS:
        VALID_CAPTCHA_TOKENS.remove(token)
        return True
    return False

def get_limit_value():
    return config.RATE_LIMIT

def rate_limit_key(request: Request):
    if "rate_limit" not in config.PROTECTION_FLAGS:
        return None
    return get_remote_address(request)

limiter = Limiter(key_func=rate_limit_key)

def verify_totp(secret: str, code: str) -> bool:
    if not secret:
        return False

    try:
        totp = pyotp.TOTP(secret, interval=30)
        # 'valid_window' is used for dealing with time sync, allowing current, previous and next window to verify
        return totp.verify(code, valid_window=1)
    except Exception as e:
        print(f"TOTP Verification Error: {e}")
        return False


def get_password_hash(password: str, algo: str) -> dict:
    if "pepper" in config.PROTECTION_FLAGS:
        password = password + config.PEPPER_SECRET

    result = {"algo": algo, "salt": None, "hash": None}
    password_bytes = password.encode('utf-8')

    if algo == config.HashAlgo.SHA256:
        # creating salt
        salt = secrets.token_hex(16)
        combined = salt + password
        hashed = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        result["salt"] = salt
        result["hash"] = hashed

    elif algo == config.HashAlgo.BCRYPT:
        # creating salt
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        result["hash"] = hashed_bytes.decode('utf-8')
        # no need to set salt because it's in the hash

    elif algo == config.HashAlgo.ARGON2:
        hashed = ph_argon2.hash(password)
        result["hash"] = hashed
        # no need to set salt because it's in the hash

    return result

def verify_password(plain_password: str, user_row) -> bool:
    if "pepper" in config.PROTECTION_FLAGS:
        plain_password = plain_password + config.PEPPER_SECRET

    algo = user_row["algo_type"]
    stored_hash = user_row["password_hash"]
    password_bytes = plain_password.encode('utf-8')

    if algo == config.HashAlgo.SHA256:
        salt = user_row["salt"]
        combined = salt + plain_password
        check_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return check_hash == stored_hash

    elif algo == config.HashAlgo.BCRYPT:
        stored_hash_bytes = stored_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)

    elif algo == config.HashAlgo.ARGON2:
        try:
            return ph_argon2.verify(stored_hash, plain_password)
        except Exception:
            return False

    return False

# Created so we will log when rate limit reached
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    username = "Unknown"

    try:
        body = await request.json()
        if isinstance(body, dict):
            username = body.get("username", "Unknown")
    except Exception:
        pass

    database.log_attempt(
        username=username,
        hash_mode="Unknown",
        result="Rate Limit Exceeded",
        latency_ms=0.0,
        protection_flags=config.PROTECTION_FLAGS
    )

    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    )
