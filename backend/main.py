from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import sys
import os
import csv
from analyzer import analyze_logs, load_logs
from collections import Counter
from datetime import datetime

# Προσθήκη του βασικού φακέλου του project στη διαδρομή αναζήτησης της Python, 
# ώστε να μπορεί να γίνει import του analyzer.py από τον φάκελο backend.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze_logs

app = FastAPI()

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
def get_analysis(): 
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
async def upload_file(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        return {
            "error": "Only CSV files are allowed"
        }

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

    with open(upload_path, "r", encoding="utf-8") as uploaded_file:
        header = uploaded_file.readline().strip().split(",")

    if not required_columns.issubset(set(header)):
        return {
            "error": "Invalid CSV format. Required columns: timestamp, user, ip, event, status"
        }
        
    with open(upload_path, "r", encoding="utf-8") as uploaded_file:
        next(uploaded_file)

        for line_number, line in enumerate(uploaded_file, start=2):
            values = line.strip().split(",")

            if len(values) != 5:
                return {
                    "error": f"Invalid data format on line {line_number}"
                }

            try:
                datetime.fromisoformat(values[0])
            except ValueError:
                return {
                    "error": f"Invalid timestamp on line {line_number}"
                }

    incidents = analyze_logs(upload_path)
    logs = load_logs(upload_path)

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