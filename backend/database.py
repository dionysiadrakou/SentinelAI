import os
import psycopg
from psycopg.errors import UniqueViolation
from dotenv import load_dotenv

def create_user(username, email, password_hash):
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")

    try:
        with psycopg.connect(database_url) as conn:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            conn.commit()

    except UniqueViolation:
        raise ValueError("Username or email already exists")
    
def get_user_by_username(username):
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")

    with psycopg.connect(database_url) as conn:
        user = conn.execute(
            """
            SELECT id, username, email, password_hash
            FROM users
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

    return user