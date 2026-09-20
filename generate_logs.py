import csv
from datetime import datetime, timedelta

output_file = "security_logs.csv"

users = ["anna", "maria", "nikos", "giorgos", "eleni"]

normal_ips = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.20",
    "192.168.1.25"
]

suspicious_ip = "192.168.1.50"

logs = []


def add_log(timestamp, user, ip, event, status):
    logs.append([
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        user,
        ip,
        event,
        status
    ])


# ============================================================
# 1. NORMAL ACTIVITY
# ============================================================

start = datetime(2026, 9, 15, 8, 0)

for i in range(720):

    # 360 events per day
    day = i // 360
    event_in_day = i % 360

    timestamp = (
        start
        + timedelta(days=day)
        + timedelta(minutes=event_in_day * 2.3)
    )

    user = users[i % len(users)]
    ip = normal_ips[i % len(normal_ips)]

    pattern = i % 12

    if pattern <= 7:
        event = "login"
        status = "success"

    elif pattern == 8:
        event = "logout"
        status = "success"

    elif pattern == 9:
        event = "password_change"
        status = "success"

    elif pattern == 10:
        event = "login"
        status = "failed"

    else:
        event = "login"
        status = "success"

    add_log(timestamp, user, ip, event, status)


# ============================================================
# 2. BRUTE FORCE
# ============================================================

start = datetime(2026, 9, 15, 16, 5)

for i in range(5):

    timestamp = start + timedelta(minutes=i)

    add_log(
        timestamp,
        "anna",
        suspicious_ip,
        "login",
        "failed"
    )


# ============================================================
# 3. UNUSUAL LOGIN
# ============================================================

add_log(
    datetime(2026, 9, 16, 3, 27),
    "maria",
    "192.168.1.15",
    "login",
    "success"
)


# ============================================================
# 4. PRIVILEGE ESCALATION
# ============================================================

start = datetime(2026, 9, 16, 11, 20)

add_log(
    start,
    "nikos",
    "192.168.1.20",
    "login",
    "success"
)

add_log(
    start + timedelta(minutes=3),
    "nikos",
    "192.168.1.20",
    "privilege_change",
    "success"
)

add_log(
    start + timedelta(minutes=4),
    "nikos",
    "192.168.1.20",
    "logout",
    "success"
)


# ============================================================
# 5. SUSPICIOUS IP
# ============================================================

start = datetime(2026, 9, 16, 14, 1)

for i, user in enumerate(users):

    timestamp = start + timedelta(minutes=i)

    add_log(
        timestamp,
        user,
        suspicious_ip,
        "login",
        "failed"
    )


# ============================================================
# 6. COMBINED ATTACK
# ============================================================

start = datetime(2026, 9, 16, 18, 10)

# Failed login attempts
for i in range(4):

    add_log(
        start + timedelta(minutes=i),
        "giorgos",
        suspicious_ip,
        "login",
        "failed"
    )

# Successful login
add_log(
    start + timedelta(minutes=4),
    "giorgos",
    suspicious_ip,
    "login",
    "success"
)

# Privilege change
add_log(
    start + timedelta(minutes=5),
    "giorgos",
    suspicious_ip,
    "privilege_change",
    "success"
)

# Password change
add_log(
    start + timedelta(minutes=6),
    "giorgos",
    suspicious_ip,
    "password_change",
    "success"
)

# Logout
add_log(
    start + timedelta(minutes=7),
    "giorgos",
    suspicious_ip,
    "logout",
    "success"
)


# ============================================================
# SORT LOGS BY TIMESTAMP
# ============================================================

logs.sort(key=lambda x: x[0])


# ============================================================
# CREATE CSV
# ============================================================

with open(output_file, "w", newline="", encoding="utf-8") as file:

    writer = csv.writer(file)

    # Header
    writer.writerow([
        "timestamp",
        "user",
        "ip",
        "event",
        "status"
    ])

    # Data
    writer.writerows(logs)


print("Security logs created successfully!")
print(f"Total logs: {len(logs)}")
print(f"File: {output_file}")