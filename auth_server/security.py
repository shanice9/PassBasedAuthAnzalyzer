import hashlib
import secrets
import bcrypt
from argon2 import PasswordHasher
import config

# argon2id setup
ph_argon2 = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1
)

def get_password_hash(password: str, algo: str) -> dict:
    if config.PEPPER_SECRET:
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
    if config.PEPPER_SECRET:
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
