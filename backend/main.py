import sys
import os
import csv
from datetime import datetime
from analyzer import analyze_logs, load_logs
from collections import Counter
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import (OAuth2PasswordRequestForm, OAuth2PasswordBearer)
from fastapi import Depends
from backend.auth import (TEST_USERNAME, TEST_PASSWORD_HASH, verify_password, create_access_token, get_current_user)

# Προσθήκη του βασικού φακέλου του project στη διαδρομή αναζήτησης της Python, 
# ώστε να μπορεί να γίνει import του analyzer.py από τον φάκελο backend.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze_logs

app = FastAPI()

# ========================================================
# JWT AUTHENTICATION
# ========================================================

# Δηλώνουμε ότι το JWT token θα βρίσκεται
# στο Authorization header του request.
#
# Το token θα έχει τη μορφή:
#
# Authorization: Bearer <JWT_TOKEN>
#
# Το tokenUrl δείχνει στο endpoint
# που χρησιμοποιείται για το login.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/login"
)

# ========================================================
# LOGIN
# ========================================================

# Endpoint για authentication του χρήστη.
#
# Ο χρήστης στέλνει username και password.
#
# Αν τα στοιχεία είναι σωστά,
# δημιουργούμε και επιστρέφουμε ένα JWT token.
@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):

    # Ελέγχουμε αν το username είναι σωστό
    # και αν το password αντιστοιχεί
    # στο αποθηκευμένο password hash.
    if (
        form_data.username != TEST_USERNAME
        or not verify_password(
            form_data.password,
            TEST_PASSWORD_HASH
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    # Δημιουργούμε JWT token
    # για τον authenticated χρήστη.
    access_token = create_access_token(
        form_data.username
    )

    # Επιστρέφουμε το token στο frontend.
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# Επιτρέπει στο React frontend να επικοινωνεί με το FastAPI backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
    # ========================================================
    # VERIFY JWT TOKEN
    # ========================================================

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
        
    incidents = analyze_logs() 
    logs = load_logs() 

    suspicious_ips = set()

    for incident in incidents.values(): 
        if "Suspicious IP Activity" in incident["threats"]: 
            suspicious_ips.add(incident["ip"])

    
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
    
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    
    # ========================================================
    # VERIFY JWT TOKEN
    # ========================================================

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
    
    # Έλεγχος αν το αρχείο που ανέβηκε είναι .csv
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are allowed"
        )

    # ========================================================
    # FILE SIZE LIMIT
    # ========================================================

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

            # Έλεγχος αν κάθε γραμμή του CSV
            # περιέχει ακριβώς 5 πεδία.
            if len(values) != 5:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid data format on line {line_number}"
                )

            # Έλεγχος αν το timestamp της συγκεκριμένης γραμμής
            # έχει έγκυρη μορφή ημερομηνίας και ώρας.
            try:
                datetime.fromisoformat(values[0])
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid timestamp on line {line_number}"
                )

    # Έλεγχος σε περίπτωση που προκύψει σφάλμα κατά την ανάλυση του CSV
    try:
        incidents = analyze_logs(upload_path)
        logs = load_logs(upload_path)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while analyzing the uploaded file."
        )

    suspicious_ips = set()

    for incident in incidents.values():
        if "Suspicious IP Activity" in incident["threats"]:
            suspicious_ips.add(incident["ip"])

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
    
