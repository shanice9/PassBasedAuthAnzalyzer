import json
import os
import sqlite3

import config
import security
import database


def load_users():
    if not os.path.exists(config.USERS_FILE):
        print(f"{config.USERS_FILE} not found, no users loaded.")
        return

    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        with open(config.USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            users_list = data.get("users", [])
            count = 0

            for user in users_list:
                username = user["username"]
                plain_password = user["password"]
                totp_secret = user.get("totp_secret")  # Can be None

                if database.user_exists(username, cursor):
                    print(f"Skipping {username}: Already exists")
                    continue

                hash_data = security.get_password_hash(plain_password, config.HASH_ALGO)

                try:
                    database.insert_user_to_db(
                        username=username,
                        algo=config.HASH_ALGO,
                        salt=hash_data["salt"],
                        hash_val=hash_data["hash"],
                        totp_secret=totp_secret,
                        cursor=cursor,
                        conn=conn
                    )
                    count += 1
                except Exception as e:
                    print(f"Error processing '{username}': {e}")

            print(f"Successfully loaded {count} new users into the database.")

    except Exception as e:
        print(f"Error loading users from file: {e}")
    finally:
        conn.close()
