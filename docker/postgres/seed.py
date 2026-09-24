import csv
import os
import psycopg

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured")

with open("/seed/security_logs.csv", "r", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("TRUNCATE TABLE security_logs")
        for row in reader:
            conn.execute(
                """
                INSERT INTO security_logs
                (timestamp, username, ip, event, status)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    row["timestamp"],
                    row["user"],
                    row["ip"],
                    row["event"],
                    row["status"]
                )
            )

        conn.commit()

print("Seeded security_logs successfully")