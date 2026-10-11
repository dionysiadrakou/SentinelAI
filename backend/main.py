import sys
import os
import csv
import psycopg
from dotenv import load_dotenv
from datetime import datetime
from backend.analyzer import analyze_logs, load_logs
import time
from collections import Counter, defaultdict
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import (OAuth2PasswordRequestForm, OAuth2PasswordBearer)
from fastapi import Depends
from backend.auth import (verify_password, create_access_token, get_current_user)
from backend.auth import hash_password
from backend.database import create_user, get_user_by_username
from pydantic import BaseModel, EmailStr, Field
import ipaddress

load_dotenv()

app = FastAPI()

LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW = 60

login_attempts = defaultdict(list)


def check_login_rate_limit(client_ip):
    now = time.monotonic()

    attempts = login_attempts[client_ip]

    # Κρατάμε μόνο τις προσπάθειες των τελευταίων 60 δευτερολέπτων.
    attempts[:] = [
        timestamp
        for timestamp in attempts
        if now - timestamp < LOGIN_RATE_WINDOW
    ]

    if len(attempts) >= LOGIN_RATE_LIMIT:
        return False

    attempts.append(now)

    return True

# Επιτρέπει requests μόνο από γνωστούς hosts.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "sentinelai-api-usc3.onrender.com"
    ]
)


#------------ SECURITY HEADERS -------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):

        # Προχωράμε κανονικά στο endpoint.
        response = await call_next(request)

        # Αποτρέπει το browser από το να "μαντεύει"
        # διαφορετικό τύπο περιεχομένου.
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Αποτρέπει το embedding της εφαρμογής
        # μέσα σε iframe από άλλο site.
        response.headers["X-Frame-Options"] = "DENY"

        # Περιορίζει το πόσο information μπορεί
        # να στείλει το browser μέσω του Referer.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Ενεργοποιεί βασική προστασία XSS σε browsers
        # που την υποστηρίζουν.
        response.headers["X-XSS-Protection"] = "1; mode=block"

        return response

# Εφαρμογή των security headers σε όλα τα responses.
app.add_middleware(SecurityHeadersMiddleware)


#------------ JWT AUTHENTICATION -------------

# Τα JWT tokens αποστέλλονται μέσω Authorization header 
# με τη μορφή: Bearer <JWT_TOKEN>.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/login"
)


#------------ LOGIN -------------

# Endpoint για authentication του χρήστη.
# Αν τα στοιχεία είναι σωστά,
# δημιουργούμε και επιστρέφουμε ένα JWT token.
@app.post("/login")
def login(request: Request,form_data: OAuth2PasswordRequestForm = Depends()):

    client_ip = request.client.host

    if not check_login_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )

    if not form_data.username or len(form_data.username) > 50:
        raise HTTPException(
            status_code=400,
            detail="Invalid username"
        )

    if not form_data.password or len(form_data.password) > 128:
        raise HTTPException(
            status_code=400,
            detail="Invalid password"
        )
        
        
    # Αναζητούμε τον χρήστη στη βάση με βάση το username.
    user = get_user_by_username(form_data.username)

    # Αν ο χρήστης δεν υπάρχει,
    # επιστρέφουμε μήνυμα αποτυχίας.
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    # Παίρνουμε το password hash από τη βάση.
    password_hash = user[3]

    # Ελέγχουμε αν το password που έδωσε ο χρήστης
    # αντιστοιχεί στο αποθηκευμένο hash.
    if not verify_password(form_data.password,password_hash):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    # Δημιουργούμε JWT token
    # για τον authenticated χρήστη.
    access_token = create_access_token(user[1])

    # Επιστρέφουμε το token στο frontend.
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# ========================================================
# USER REGISTRATION
# ========================================================

class RegisterRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[A-Za-z0-9_.-]+$"
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128
    )

@app.post("/register")
def register(user_data: RegisterRequest):
    # Ελέγχουμε ότι το username δεν είναι κενό.
    if not user_data.username.strip():
        raise HTTPException(
            status_code=400,
            detail="Username is required"
        )

    # Ελέγχουμε ότι το email δεν είναι κενό.
    if not user_data.email.strip():
        raise HTTPException(
            status_code=400,
            detail="Email is required"
        )

    # Ελέγχουμε ότι το password δεν είναι κενό.
    if not user_data.password:
        raise HTTPException(
            status_code=400,
            detail="Password is required"
        )

    # Ελάχιστο μήκος password.
    if len(user_data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )

    # Μετατρέπουμε το password σε ασφαλές hash.
    password_hash = hash_password(user_data.password)

    try:
        # Αποθηκεύουμε τον νέο χρήστη στη βάση.
        create_user(user_data.username.strip(), user_data.email.strip(), password_hash)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    return {
        "message": "User registered successfully"
    }



# Επιτρέπει στο React frontend να επικοινωνεί με το FastAPI backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Έλεγχος ότι το API λειτουργεί.
@app.get("/")
def home():
    return {"message": "SentinelAI API is running"}


# Ανάλυση των security logs και επιστροφή των περιστατικών που εντοπίστηκαν.
@app.get("/analyze") 
def get_analysis(token: str = Depends(oauth2_scheme)): 
    
    # Ελέγχουμε αν το JWT token που έστειλε ο χρήστης είναι έγκυρο.
    current_user = get_current_user(token)

    # Αν το token δεν είναι έγκυρο,
    # επιστρέφουμε HTTP 401 Unauthorized.
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
        
    # Εκτελούμε την ανάλυση και φορτώνουμε τα logs.
    incidents = analyze_logs() 
    logs = load_logs() 

    # Εντοπίζουμε τις ύποπτες IPs.
    suspicious_ips = set()

    for incident in incidents.values(): 
        if "Suspicious IP Activity" in incident["threats"]: 
            suspicious_ips.add(incident["ip"])

    # Μετράμε τα events ανά ώρα.
    events_by_hour = Counter()
    for log in logs:
        hour = log["timestamp"].strftime("%H:00")
        events_by_hour[hour] += 1

    return { 
        "total_events": len(logs), 
        "total_incidents": len(incidents), 
        "suspicious_ips": len(suspicious_ips),
        "events_over_time": [ 
            {"time": hour, "count": count} 
            for hour, count in sorted(events_by_hour.items()) 
        ],
        "incidents": list(incidents.values()) 
    }
    
   
def save_uploaded_logs_to_database(logs):
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")

    with psycopg.connect(database_url) as conn:
        conn.execute("TRUNCATE TABLE uploaded_security_logs")

        for log in logs:
            conn.execute(
                """
                INSERT INTO uploaded_security_logs
                (timestamp, username, ip, event, status)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    log["timestamp"],
                    log["user"],
                    log["ip"],
                    log["event"],
                    log["status"]
                )
            )

        conn.commit()
   
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    # Ελέγχουμε αν το JWT token που έστειλε
    # ο χρήστης είναι έγκυρο.
    current_user = get_current_user(token)

    # Αν το token δεν είναι έγκυρο,
    # επιστρέφουμε HTTP 401 Unauthorized.
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
    
    # Επιτρέπουμε μόνο αρχεία CSV.
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are allowed"
        )

    # Μέγιστο επιτρεπόμενο μέγεθος αρχείου: 5 MB.
    MAX_FILE_SIZE = 5 * 1024 * 1024

    # Ελέγχουμε το μέγεθος του uploaded αρχείου.
    if file.size is not None and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File is too large. Maximum size is 5 MB."
        )

    contents = await file.read()

    upload_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "uploaded_security_logs.csv"
    )

    with open(upload_path, "wb") as output_file:
        output_file.write(contents)

    # Απαιτούμενες στήλες του CSV.
    required_columns = {
        "timestamp",
        "user",
        "ip",
        "event",
        "status"
    }

    with open(upload_path, "r", encoding="utf-8", newline="") as uploaded_file:
        reader = csv.reader(uploaded_file)
        try:
            header = next(reader)
        except StopIteration:
            header = []

    # Έλεγχος αν το αρχείο .csv είναι άδειο
    if not header:
        raise HTTPException(
            status_code=400,
            detail="CSV file is empty"
        )

    # Αφαιρούμε τυχόν κενά από τα ονόματα των στηλών.
    header = [column.strip() for column in header]

    # Έλεγχος αν το CSV περιέχει όλες τις απαιτούμενες στήλες.
    if not required_columns.issubset(set(header)):
        raise HTTPException(
            status_code=400,
            detail="Invalid CSV format. Required columns: timestamp, user, ip, event, status"
        )
            
    with open(upload_path, "r", encoding="utf-8", newline="") as uploaded_file:

        reader = csv.reader(uploaded_file)

        # Παραλείπουμε τη γραμμή με τα ονόματα των στηλών.
        next(reader)

        # Διαβάζουμε κάθε γραμμή του CSV.
        for line_number, values in enumerate(reader, start=2):

            # Κάθε γραμμή πρέπει να περιέχει ακριβώς 5 πεδία.
            if len(values) != 5:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid data format on line {line_number}"
                )

            timestamp_value = values[0].strip()
            user_value = values[1].strip()
            ip_value = values[2].strip()
            event_value = values[3].strip()
            status_value = values[4].strip()

            # Έλεγχος timestamp.
            try:
                datetime.fromisoformat(timestamp_value)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid timestamp on line {line_number}"
                )

            # Έλεγχος username.
            if (
                not user_value
                or len(user_value) > 100
                or not user_value.isprintable()
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid username on line {line_number}"
                )

            # Έλεγχος IP address.
            try:
                ipaddress.ip_address(ip_value)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid IP address on line {line_number}"
                )

            # Έλεγχος event.
            allowed_events = {
                "login",
                "logout",
                "privilege_change",
                "password_change"
            }

            if (
                not event_value
                or len(event_value) > 100
                or event_value not in allowed_events
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid event on line {line_number}"
                )

            # Έλεγχος status.
            allowed_statuses = {
                "success",
                "failed"
            }

            if (
                not status_value
                or len(status_value) > 50
                or status_value not in allowed_statuses
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status on line {line_number}"
                )

    uploaded_logs = load_logs(upload_path)
    save_uploaded_logs_to_database(uploaded_logs)
    
    # Έλεγχος σε περίπτωση που προκύψει σφάλμα κατά την ανάλυση του CSV
    try:
        incidents = analyze_logs(use_uploaded_db=True)
        logs = load_logs(use_uploaded_db=True)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while analyzing the uploaded file."
        )

    # Εντοπίζουμε τις ύποπτες IPs.
    suspicious_ips = set()

    for incident in incidents.values():
        if "Suspicious IP Activity" in incident["threats"]:
            suspicious_ips.add(incident["ip"])

    # Μετράμε τα events ανά ώρα.
    events_by_hour = Counter()

    for log in logs:
        hour = log["timestamp"].strftime("%H:00")
        events_by_hour[hour] += 1

    return {
        "filename": file.filename,
        "message": "File uploaded and analyzed successfully",
        "total_events": len(logs),
        "total_incidents": len(incidents),
        "suspicious_ips": len(suspicious_ips),
        "events_over_time": [
            {"time": hour, "count": count}
            for hour, count in sorted(events_by_hour.items())
        ],
        "incidents": list(incidents.values())
    }
    