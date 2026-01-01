import time
import sqlite3
import uvicorn
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

import config
import security
import database
import loaders

app = FastAPI(title="Auth Server")
app.state.limiter = security.limiter
app.add_exception_handler(RateLimitExceeded, security.custom_rate_limit_handler)

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
@security.limiter.limit(security.get_limit_value)
def register(req: RegisterRequest, request: Request, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    cursor = conn.cursor()

    if database.user_exists(req.username, cursor):
        raise HTTPException(status_code=400, detail="Username already exists")

    hash_data = security.get_password_hash(req.password, config.HASH_ALGO)

    try:
        database.insert_user_to_db(
            username=req.username,
            algo=config.HASH_ALGO,
            salt=hash_data["salt"],
            hash_val=hash_data["hash"],
            totp_secret=req.totp_secret,
            cursor=cursor,
            conn=conn
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": "User created successfully",
        "username": req.username,
        "totp_secret": req.totp_secret
    }


@app.post("/login")
@security.limiter.limit(security.get_limit_value)
def login(req: LoginRequest, request: Request, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    # For logs
    start_time = time.time()

    result_str = "Password login | Invalid credentials"
    totp_enabled = "totp" in config.PROTECTION_FLAGS
    login_success = False
    cursor = conn.cursor()
    # Gets user data
    user = database.get_user(req.username, cursor)
    hash_mode = user["algo_type"] if user else "Unknown"
    totp_secret = user["totp_secret"] if user else None
    totp_required = totp_enabled and totp_secret

    if user and security.verify_password(req.password, user):
        login_success = True
        result_str = "Password login | Login Successful"
        if totp_required:
            result_str = "Password login | TOTP required"

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    database.log_attempt(
        username=req.username,
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
@security.limiter.limit(security.get_limit_value)
def login_totp(req: TOTPLoginRequest, request: Request, conn: sqlite3.Connection = Depends(database.get_db_conn)):
    # For logs
    start_time = time.time()

    result_str = "TOTP login | Invalid TOTP code"
    login_success = False

    cursor = conn.cursor()
    user = database.get_user(req.username, cursor)
    hash_mode = user["algo_type"] if user else "Unknown"
    secret = user["totp_secret"] if user else None

    if user and secret:
        if security.verify_totp(secret, req.totp_code):
            login_success = True
            result_str = "TOTP login | TOTP valid, login completed"
    else:
        result_str = "TOTP login | User has no TOTP secret setup"

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    database.log_attempt(
        username=req.username,
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
        "username": req.username,
        "valid": True
    }

if __name__ == "__main__":
    config.load_config()
    config.load_group_seed()
    database.init_db()
    loaders.load_users()

    uvicorn.run(app, host="0.0.0.0", port=8000)
