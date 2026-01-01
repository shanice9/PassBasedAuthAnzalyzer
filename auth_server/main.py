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
    start_time = time.time()
    hash_mode = "Unknown"
    login_success = False
    cursor = conn.cursor()

    # Fetch user data
    cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
    user = cursor.fetchone()

    if user:
        hash_mode = user["algo_type"]
        if security.verify_password(request.password, user):
            login_success = True

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    result_str = "Login successful" if login_success else "Invalid credentials"

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


if __name__ == "__main__":
    config.load_config()
    config.load_group_seed()
    database.init_db()
    loaders.load_users()

    uvicorn.run(app, host="0.0.0.0", port=8000)
