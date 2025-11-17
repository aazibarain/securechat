import os
import pymysql
from dotenv import load_dotenv
from pathlib import Path

# Explicitly point to .env in the project root
env_path = Path.cwd() / '.env'
print("Looking for .env at:", env_path)
load_dotenv(dotenv_path=str(env_path))

# show a couple env values for debugging
print("DB_HOST =", os.getenv("DB_HOST"))
print("DB_USER =", os.getenv("DB_USER"))
print("DB_NAME =", os.getenv("DB_NAME"))

# Attempt connection
conn = pymysql.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASS'),
    db=os.getenv('DB_NAME'),
    port=int(os.getenv('DB_PORT', 3306))
)
cur = conn.cursor()
cur.execute("SELECT VERSION()")
print("MySQL OK:", cur.fetchone())
conn.close()
