from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys
import os
from analyzer import analyze_logs, load_logs
from collections import Counter

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
