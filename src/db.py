# src/db.py
from pathlib import Path
import os
import pymysql
from dotenv import load_dotenv

def db_connect():
    env_path = Path.cwd() / ".env"
    load_dotenv(dotenv_path=str(env_path))
    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        user=os.getenv("DB_USER", "securechat_user"),
        password=os.getenv("DB_PASS", ""),
        db=os.getenv("DB_NAME", "securechat_db"),
        port=int(os.getenv("DB_PORT", 3306)),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )
    return conn
