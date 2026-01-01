import time
import sqlite3
import uvicorn
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel

# Import our new modules
import config
import security
import database
import loaders

app = FastAPI(title="Auth Server")


class TOTPLoginRequest(BaseModel):
    username: str
    totp_code: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    totp_secret: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/register")
def register(request: RegisterRequest, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    cursor = conn.cursor()

    if database.user_exists(request.username, cursor):
        raise HTTPException(status_code=400, detail="Username already exists")

    hash_data = security.get_password_hash(request.password, config.HASH_ALGO)

    try:
        database.insert_user_to_db(
            username=request.username,
            algo=config.HASH_ALGO,
            salt=hash_data["salt"],
            hash_val=hash_data["hash"],
            totp_secret=request.totp_secret,
            cursor=cursor,
            conn=conn
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": "User created successfully",
        "username": request.username,
        "totp_secret": request.totp_secret
    }


@app.post("/login")
def login(request: LoginRequest, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    # For logs
    start_time = time.time()

    result_str = "Password login | Invalid credentials"
    totp_enabled = "totp" in config.PROTECTION_FLAGS
    login_success = False
    cursor = conn.cursor()
    # Gets user data
    user = database.get_user(request.username, cursor)
    hash_mode = user["algo_type"] if user else "Unknown"
    totp_secret = user["totp_secret"] if user else None
    totp_required = totp_enabled and totp_secret

    if user and security.verify_password(request.password, user):
        login_success = True
        result_str = "Password login | Login Successful"
        if totp_required:
            result_str = "Password login | TOTP required"

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    database.log_attempt(
        username=request.username,
        hash_mode=hash_mode,
        result=result_str,
        latency_ms=latency_ms,
        protection_flags=config.PROTECTION_FLAGS
    )

    if not login_success:
        raise HTTPException(status_code=401, detail=result_str)

    return {
        "message": result_str,
        "user_id": user["id"],
        "username": user["username"]
    }


@app.post("/login_totp")
def login_totp(request: TOTPLoginRequest, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    # For logs
    start_time = time.time()

    result_str = "TOTP login | Invalid TOTP code"
    login_success = False

    cursor = conn.cursor()
    user = database.get_user(request.username, cursor)
    hash_mode = user["algo_type"] if user else "Unknown"
    secret = user["totp_secret"] if user else None

    if user and secret:
        if security.verify_totp(secret, request.totp_code):
            login_success = True
            result_str = "TOTP login | TOTP valid, login completed"
    else:
        result_str = "TOTP login | User has no TOTP secret setup"

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    database.log_attempt(
        username=request.username,
        hash_mode=hash_mode,
        result=result_str,
        latency_ms=latency_ms,
        protection_flags=config.PROTECTION_FLAGS
    )

    if not login_success:
        raise HTTPException(status_code=401, detail=result_str)

    return {
        "message": "Login successful",
        "user_id": user["id"],
        "username": request.username,
        "valid": True
    }

if __name__ == "__main__":
    config.load_config()
    config.load_group_seed()
    database.init_db()
    loaders.load_users()

    uvicorn.run(app, host="0.0.0.0", port=8000)
