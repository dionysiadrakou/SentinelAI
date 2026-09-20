from collections import Counter
import csv
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest

LOG_FILE = "C:\\Users\\dionysia\\Desktop\\portofolio\\SentinelAI\\security_logs.csv"

# Ο ελάχιστος αριθμός αποτυχημένων login attempts 
# που απαιτούνται για να θεωρήσουμε ότι υπάρχει πιθανό Brute Force.
FAILED_ATTEMPTS_THRESHOLD = 3

# Το χρονικό διάστημα μέσα στο οποίο πρέπει 
# να συμβούν οι αποτυχημένες προσπάθειες.
TIME_WINDOW_MINUTES = 5

def load_logs():
    logs = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        # Το DictReader διαβάζει κάθε γραμμή του CSV 
        # και τη μετατρέπει σε dictionary. 
        # 
        # Για παράδειγμα:
        # timestamp,user,ip,event,status  
        
        # γίνεται: 
        
        # { 
        #   "timestamp": "...", 
        #   "user": "anna", 
        #   "ip": "192.168.1.50", 
        #   "event": "login", 
        #   "status": "failed" 
        # }
        reader = csv.DictReader(file)

        for row in reader:
            # Το timestamp αρχικά είναι string και μετά το μετατρέπουμε σε datetime
            row["timestamp"] = datetime.strptime(
                row["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            # προσθέτουμε το log στη λίστα
            logs.append(row)

    return logs

#### BRUTE FORCE ####
def detect_brute_force(logs):
    # Αποθηκεύουμε όλα τα alerts που θα δημιουργηθούν
    alerts = []

    # Κρατάμε μόνο τα failed logs
    failed_logins = [
        log for log in logs
        if log["event"] == "login"
        and log["status"] == "failed"
    ]

    # Ταξινόμηση των failed logs με βάση τον χρόνο
    # key=lambda log: log["timestamp"] σημαίνει "χρησιμοποίησε το 
    # timestamp για να αποφασίσεις τη σειρά των logs"
    failed_logins.sort(key=lambda log: log["timestamp"])

    # Δημιουργούμε ένα set και σε αυτό αποθηκεύουμε τα failed login
    # attempts που έχουν ήδη συμπεριήφθεί σε κάποιο Brute Force Incident.
    processed_attempts = set()

    # Εξετάζουμε κάθε failed login
    for current_log in failed_logins:

        # Κρατάμε το id του dictionary object για να το ξεχωρίζουμε
        current_id = id(current_log)

        # Αν το συγκεκριμένο attempt έχει ήδη χρησιμοποιηθεί
        # σε προηγούμενο BF incident, δεν χρειαζεται να το ξαναδούμε
        if current_id in processed_attempts:
            continue

        # Δημιουργούμε το χρονικό παράθυρο από το timestamp του current login
        window_start = current_log["timestamp"]
        
        # Το τέλος του παραθύρου είναι 5 λεπτά μετά
        window_end = window_start + timedelta(
            minutes=TIME_WINDOW_MINUTES
        )

        # Βρίσκουμε τα failed logins μέσα στο παράθυρο
        matching_attempts = [
            log for log in failed_logins
            if log["user"] == current_log["user"]
            and log["ip"] == current_log["ip"]
            and window_start <= log["timestamp"] <= window_end
        ]

        # Ελέγχουμε αν υπάρχουν αρκετά attempts (δηλαδή τουλάχιστον 3)
        if len(matching_attempts) >= FAILED_ATTEMPTS_THRESHOLD:

            # Σημειώνουμε αυτές τις προσπάθειες ως processed
            # Όλα τα attempts που συμμετείχαν στο συγκεκριμένο incident
            # τα σημειώνουμε ως ήδη "επεξεργασμένα"
            for log in matching_attempts:
                processed_attempts.add(id(log))

            # Δημιουργούμε το Brute Force Alert
            alerts.append({
                "type": "Brute Force",
                "user": current_log["user"],
                "ip": current_log["ip"],
                "attempts": len(matching_attempts),
                "risk_score": 75,
                "severity": "HIGH"
            })

    return alerts

# UNUSUAL LOGIN
def detect_unusual_login(logs):
    alerts = []

    # Ελέγχουμε δύο πράγματα:
    # 1. ότι το event είναι login
    # 2. οτι το status ειναι επιτυχές
    for log in logs:
        # Μας ενδιαφέρουν δηλαδή μόνο τα successful logins.
        if log["event"] == "login" and log["status"] == "success":
            # Παίρνουμε μόνο την ώρα
            hour = log["timestamp"].hour

            # Ελέγχουμε αν η ώρα είναι από 00:00 μέχρι 05:00
            if 0 <= hour < 5:
                # Αν ισχύει η συνθήκη, δημιουργούμε νέο alert
                alerts.append({
                    "type": "Unusual Login",
                    "user": log["user"],
                    "ip": log["ip"],
                    "timestamp": log["timestamp"],
                    "risk_score": 50,
                    "severity": "MEDIUM"
                })

    return alerts

# DETECT PRIVILEGE ESCALATION
def detect_privilege_escalation(logs):
    alerts = []

    # Εξετάζουμε όλα τα logs ένα-ένα
    # το i είναι η θέση του log στη λίστα
    # το log είναι το ίδιο συγκεκριμένο log
    for i, log in enumerate(logs):

        # Ελέγχουμε αν έγινε επιτυχής αλλαγή δικαιωμάτων
        if (
            log["event"] == "privilege_change"
            and log["status"] == "success"
        ):
            # Εφόσον βρήκαμε privilege change, κοιτάμε τα logs 
            # που βρίσκονται ΠΡΙΝ από αυτή τη λίστα
            # Ελέγχουμε προηγούμενα logs
            for previous_log in logs[:i]:

                # Ψάχνουμε αν υπάρχει προηγούμενο successful login
                # 1. από τον ίδιο χρήστη
                # 2. από την ίδια IP
                # 3. με event=login
                # 4. με status=success
                if (
                    previous_log["user"] == log["user"]
                    and previous_log["ip"] == log["ip"]
                    and previous_log["event"] == "login"
                    and previous_log["status"] == "success"
                ):

                    # Υπολογίζουμε πόσα λεπτά πέρασαν από το
                    # successful login μέχρι το privilege change
                    time_difference = (
                        log["timestamp"] - previous_log["timestamp"]
                    ).total_seconds() / 60

                    # Το login πρέπει να έχει γίνει
                    # μέσα στα προηγούμενα 10 λεπτά
                    if 0 <= time_difference <= 10:
                        # Δημιουργούμε ένα Privilege Escalation alert.
                        alerts.append({
                            "type": "Privilege Escalation",
                            "user": log["user"],
                            "ip": log["ip"],
                            "timestamp": log["timestamp"],
                            "risk_score": 70,
                            "severity": "HIGH"
                        })
                        break
    return alerts

###### SUSPICIOUS IP ######
def detect_suspicious_ip(logs):
    alerts = []

    # Κρατάμε μόνο τα failed login attempts
    failed_logins = [
        log for log in logs
        if log["event"] == "login"
        and log["status"] == "failed"
    ]

    # Ταξινομούμε τα failed logins από το παλαιότερο προς το νεότερο.
    # Το timestamp χρησιμοποιείται ως κριτήριο ταξινόμησης.
    failed_logins.sort(key=lambda log: log["timestamp"])

    # Δημιουργούμε ένα set για να θυμόμαστε 
    # ποιες IP έχουμε ήδη επεξεργαστεί.
    processed_ips = set()

    # Εξετάζουμε ένα-ένα τα failed login attempts
    for current_log in failed_logins:
        # Παίρνουμε την IP του συγκεκριμένου log
        ip = current_log["ip"]

        # Αν έχουμε ήδη εξετάσει αυτή την IP 
        # και έχουμε δημιουργήσει alert για αυτή, την προσπερνάμε.
        if ip in processed_ips:
            continue

        # Δημιουργούμε χρονικό παράθυρο 5 λεπτών
        # Αρχή του παραθύρου: 
        # η ώρα του τρέχοντος failed login
        window_start = current_log["timestamp"]
        
        # Τέλος του παραθύρου: 5 λεπτά μετά
        window_end = window_start + timedelta(minutes=5)

        # Βρίσκουμε όλα τα failed login attempts 
        # που προέρχονται από την ίδια IP 
        # και έγιναν μέσα στο συγκεκριμένο 5λεπτο.
        matching_attempts = [
            log for log in failed_logins
            if log["ip"] == ip
            and window_start <= log["timestamp"] <= window_end
        ]

        # Βρίσκουμε πόσους διαφορετικούς χρήστες στόχευσε 
        # η συγκεκριμένη IP
        users_targeted = set(
            log["user"]
            for log in matching_attempts
        )

        # Το set κρατάει μόνο μοναδικούς χρήστες. 
        # Ελέγχουμε αν η IP είναι ύποπτη
        #
        # Η IP θεωρείται ύποπτη αν ισχύει 
        # τουλάχιστον μία από τις δύο συνθήκες: 
        #
        # 1. Έχει κάνει 5 ή περισσότερα failed logins 
        # Ή 
        # 2. Έχει στοχεύσει 3 ή περισσότερους διαφορετικούς χρήστες.
        if (
            len(matching_attempts) >= 5
            or len(users_targeted) >= 3
        ):

            # Σημειώνουμε την IP ως επεξεργασμένη
            # ώστε να μην ξαναδημιουργηθεί 
            # το ίδιο alert για αυτή την IP.
            processed_ips.add(ip)

            # Δημιουργούμε το Suspicious IP alert
            alerts.append({
                "type": "Suspicious IP Activity",
                "ip": ip,
                "failed_attempts": len(matching_attempts),
                "users_targeted": len(users_targeted),
                "risk_score": 80,
                "severity": "CRITICAL"
            })

    return alerts

###### ML Συνάρτηση - Anomaly Detection ######
def detect_anomalies(logs):
    """
    Detect unusual user/IP behavior using Isolation Forest.
    """
    # Λίστα που θα περιέχει τα feature vectors
    # που θα δώσουμε στο Machine Learning μοντέλο.
    features = []
    
    # Λίστα που κρατάει πληροφορίες για το
    # σε ποιον user και IP αντιστοιχεί κάθε feature vector.
    metadata = []

    # ============================================
    # 1. Group logs by user + IP
    # ============================================

    # Δημιουργούμε ένα άδειο dictionary.
    # Θα χρησιμοποιηθεί για να ομαδοποιήσουμε τα logs ανά χρήστη και IP.
    groups = {}

    for log in logs:

        # Δημιουργούμε ένα key που αποτελείται από τον χρήστη και την IP.
        key = (log["user"], log["ip"])

        # Αν αυτός ο συνδυασμός user + IP δεν υπάρχει ακόμα στο dictionary, 
        # δημιουργούμε μια άδεια λίστα.
        if key not in groups:
            groups[key] = []

        # Προσθέτουμε το συγκεκριμένο log στην αντίστοιχη ομάδα.
        groups[key].append(log)


    # ============================================
    # 2. Create features for each user + IP
    # ============================================

    # Παίρνουμε κάθε ομάδα user + IP και όλα τα logs που ανήκουν σε αυτή.
    for (user, ip), user_logs in groups.items():

        # Feature 1: Total Events
        # Μετράμε πόσα συνολικά events έχει αυτή η ομάδα user + IP.
        total_events = len(user_logs)

        # Feature 2: Failed Logins
        # Μετράμε πόσα failed login attempts υπάρχουν.
        failed_logins = sum(
            1 for log in user_logs
            if log["event"] == "login"
            and log["status"] == "failed"
        )

        # Feature 3: Successful Logins
        # Μετράμε πόσα successful login attempts υπάρχουν.
        successful_logins = sum(
            1 for log in user_logs
            if log["event"] == "login"
            and log["status"] == "success"
        )

        # Feature 4: Privilege Changes
        # Μετράμε πόσες επιτυχημένες αλλαγές δικαιωμάτων έγιναν.
        privilege_changes = sum(
            1 for log in user_logs
            if log["event"] == "privilege_change"
            and log["status"] == "success"
        )

        # Feature 5: Password Changes
        # Μετράμε πόσες επιτυχημένες αλλαγές κωδικού έγιναν.
        password_changes = sum(
            1 for log in user_logs
            if log["event"] == "password_change"
            and log["status"] == "success"
        )

        # FEATURE 6: FAILED LOGIN RATE
        # Υπολογίζουμε το ποσοστό των events που είναι failed login attempts.
        failed_login_rate = (
            failed_logins / total_events
            if total_events > 0
            else 0
        )

        # FEATURE 7: NIGHT-TIME SUCCESSFUL LOGINS
        # Μετράμε πόσα successful logins έγιναν μεταξύ 00:00 και 04:59.
        night_logins = sum(
            1 for log in user_logs
            if log["event"] == "login"
            and log["status"] == "success"
            and 0 <= log["timestamp"].hour < 5
        )

        # FEATURE 8: NUMBER OF DIFFERENT IPs
        # Βρίσκουμε πόσες διαφορετικές IPs έχει χρησιμοποιήσει συνολικά ο συγκεκριμένος χρήστης. 
        # Το set αφαιρεί τις διπλότυπες IPs.
        unique_ips = len(
            set(log["ip"] for log in logs
                if log["user"] == user)
        )

        # ========================================
        # Feature vector
        # ========================================
        # Μαζεύουμε όλα τα features σε μία αριθμητική λίστα.
        features.append([
            total_events,
            failed_logins,
            successful_logins,
            failed_login_rate,
            privilege_changes,
            password_changes,
            night_logins,
            unique_ips
        ])

        metadata.append({
            "user": user,
            "ip": ip
        })


    # ============================================
    # 3. Train Isolation Forest
    # ============================================

    # Αν έχουμε λιγότερα από 2 feature vectors, δεν έχει νόημα να ψάξουμε anomalies.
    if len(features) < 2:
        return []

    # Δημιουργούμε ένα Isolation Forest model.
    # Υποθέτουμε ότι περίπου το 5% των observations μπορεί να είναι anomalies. 
    # Σταθεροποιούμε το random μέρος του αλγορίθμου ώστε να έχουμε ίδια αποτελέσματα στις επαναλήψεις.
    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    # Δίνουμε τα feature vectors στο μοντέλο.
    # Το fit_predict(): 
    # 1. κάνει fit/train το μοντέλο στα δεδομένα 
    # 2. κάνει prediction για κάθε feature vector
    predictions = model.fit_predict(features)

    # ============================================
    # 4. Create anomaly alerts
    # ============================================

    # Κενή λίστα για τα ML anomaly alerts.
    anomalies = []

    # Εξετάζουμε ταυτόχρονα: 
    # prediction -> αποτέλεσμα του ML 
    # info -> user + IP 
    # feature -> feature vector 
    # 
    # Το zip τα "ενώνει" μεταξύ τους.
    for prediction, info, feature in zip(
        predictions,
        metadata,
        features
    ):

        # Στο Isolation Forest: 
        # 
        # 1 = normal 
        # -1 = anomaly 
        #
        # Άρα εξετάζουμε μόνο τα anomalies.
        if prediction == -1:
            # Παίρνουμε ξανά τις τιμές από το feature vector.
            total_events = feature[0]
            failed_logins = feature[1]
            successful_logins = feature[2]
            failed_login_rate = feature[3]
            privilege_changes = feature[4]
            password_changes = feature[5]
            night_logins = feature[6]
            unique_ips = feature[7]

            # Δημιουργούμε μια κενή λίστα για να αποθηκεύσουμε τους λόγους
            reasons = []

            # Αν υπάρχουν τουλάχιστον 3 failed logins, προσθέτουμε αυτόν τον λόγο.
            if failed_logins >= 3:
                reasons.append(
                    "Multiple failed login attempts"
                )

            # Αν τουλάχιστον το 50% των events είναι failed logins, προσθέτουμε αυτόν τον λόγο.
            if failed_login_rate >= 0.5:
                reasons.append(
                    "High failed login rate"
                )

            # Αν υπάρχει privilege change, το αναφέρουμε στην εξήγηση.
            if privilege_changes > 0:
                reasons.append(
                    "Privilege changes detected"
                )

            # Αν υπάρχει password change, το αναφέρουμε στην εξήγηση.
            if password_changes > 0:
                reasons.append(
                    "Password changes detected"
                )

            # Αν υπάρχει successful login κατά τις ασυνήθιστες ώρες, το αναφέρουμε.
            if night_logins > 0:
                reasons.append(
                    "Login activity during unusual hours"
                )

            # Αν ο χρήστης έχει χρησιμοποιήσει περισσότερες από μία IP, το αναφέρουμε.
            if unique_ips > 1:
                reasons.append(
                    "User accessed the system from multiple IPs"
                )

            # ----------------------------------------
            # Fallback explanation
            # ----------------------------------------

            # Αν το ML εντόπισε anomaly αλλά κανένας από τους παραπάνω κανόνες 
            # δεν βρήκε συγκεκριμένο χαρακτηριστικό, χρησιμοποιούμε μια γενική εξήγηση.
            if not reasons:
                reasons.append(
                    "Behavior differs from other user/IP profiles"
                )

            # Ενώνουμε όλους τους λόγους σε ένα ενιαίο string.
            explanation = "; ".join(reasons)

            # Δημιουργούμε το anomaly alert και το προσθέτουμε στη λίστα.
            anomalies.append({
                "type": "ML Anomaly",
                "user": info["user"],
                "ip": info["ip"],
                "events": total_events,
                "failed_logins": failed_logins,
                "successful_logins": successful_logins,
                "failed_login_rate": failed_login_rate,
                "privilege_changes": privilege_changes,
                "password_changes": password_changes,
                "night_logins": night_logins,
                "unique_ips": unique_ips,
                "explanation": explanation,
                "risk_score": 65,
                "severity": "HIGH"
            })

    return anomalies

def calculate_risk(alerts):
    
    # Δημιουργούμε ένα άδειο dictionary. 
    # Εδώ θα αποθηκεύσουμε τα incidents. 
    # Κάθε incident θα αντιστοιχεί σε έναν συγκεκριμένο user + IP.
    incidents = {}

    # ============================================
    # 1. Group alerts into incidents
    # ============================================

    for alert in alerts:

        # Αν το alert περιέχει user, δημιουργούμε ως key: (user, IP)
        if "user" in alert:
            key = (alert["user"], alert["ip"])
            
        # Αν το alert ΔΕΝ περιέχει user, χρησιμοποιούμε: ("UNKNOWN", IP) 
        # Αυτό συμβαίνει για alerts που αφορούν μόνο μία IP, όπως το Suspicious IP Activity.
        else:
            key = ("UNKNOWN", alert["ip"])

        # Ελέγχουμε αν έχουμε ήδη δημιουργήσει incident για αυτό το user + IP.
        if key not in incidents:
            # Αν δεν υπάρχει, δημιουργούμε νέο incident.
            incidents[key] = {
                "user": key[0],
                "ip": key[1],
                "threats": []
            }

        # Προσθέτουμε τον τύπο του alert # στη λίστα των threats. 
        # Ελέγχουμε πρώτα αν υπάρχει ήδη,ωώστε να μην έχουμε duplicate threats.
        if alert["type"] not in incidents[key]["threats"]:
            incidents[key]["threats"].append(alert["type"])


    # ============================================
    # 2. Associate IP-based alerts with users
    # ============================================

    # Εξετάζουμε τα incidents που δημιουργήθηκαν. Το list(...) δημιουργεί αντίγραφο των keys, 
    # ώστε να μπορούμε να διαγράψουμε στοιχεία από το αρχικό dictionary μέσα στο loop.
    for unknown_key in list(incidents.keys()):

        # Αν το incident έχει κανονικό user και όχι UNKNOWN, δεν χρειάζεται να κάνουμε κάτι.
        if unknown_key[0] != "UNKNOWN":
            continue

        # Παίρνουμε την IP από το UNKNOWN incident.
        ip = unknown_key[1]

        # Παίρνουμε τα threats που έχουν συνδεθεί με αυτή την IP.
        ip_threats = incidents[unknown_key]["threats"]

        # Ψάχνουμε όλα τα incidents που: 
        # 1. έχουν συγκεκριμένο user 
        # 2. έχουν την ίδια IP 
        # Έτσι μπορούμε να συνδέσουμε το IP-based alert με τους αντίστοιχους users.
        matching_incidents = [
            key for key in incidents
            if key[0] != "UNKNOWN"
            and key[1] == ip
        ]

        # Για κάθε user + IP incident που χρησιμοποιεί αυτή την IP...
        for key in matching_incidents:

            # Παίρνουμε κάθε threat που είχε συνδεθεί μόνο με την IP.
            for threat in ip_threats:

                # Αν το συγκεκριμένο threat δεν υπάρχει ήδη στο incident...
                if threat not in incidents[key]["threats"]:
                    # ...το προσθέτουμε.
                    incidents[key]["threats"].append(threat)

        # Αφού συνδέσαμε το IP-based alert με τους αντίστοιχους users,
        # διαγράφουμε το UNKNOWN incident.
        del incidents[unknown_key]


    # ============================================
    # 3. Base scores for rule-based threats
    # ============================================

    # Ορίζουμε ένα βασικό risk score για κάθε rule-based threat. 
    # Αυτές οι τιμές είναι δικές μας σχεδιαστικές επιλογές για το project.

    threat_scores = {
        "Brute Force": 75,
        "Privilege Escalation": 70,
        "Suspicious IP Activity": 80,
        "Unusual Login": 50
    }


    # ============================================
    # 4. Calculate risk score
    # ============================================

    for incident in incidents.values():

        # Παίρνουμε τη λίστα με τα threats του συγκεκριμένου incident.
        threats = incident["threats"]

        # ----------------------------------------
        # Find the most serious rule-based threat
        # ----------------------------------------

        # Κρατάμε μόνο τα threats που υπάρχουν στο threat_scores, Δηλαδή τα rule-based threats. 
        # Το ML Anomaly δεν υπάρχει εδώ, γιατί θέλουμε να το χειριστούμε ξεχωριστά.
        rule_threats = [
            threat for threat in threats
            if threat in threat_scores
        ]

        # Αν υπάρχει τουλάχιστον ένα rule-based threat...
        if rule_threats:
            # Παίρνουμε το μεγαλύτερο βασικό score.
            score = max(
                threat_scores[threat]
                for threat in rule_threats
            )
        # Αν δεν υπάρχει κανένα rule-based threat, ξεκινάμε από score 0.
        else:
            score = 0


        # ----------------------------------------
        # Multiple rule-based threats
        # ----------------------------------------
        
        # Μετράμε πόσα διαφορετικά rule-based threats υπάρχουν.
        number_of_rule_threats = len(rule_threats)

        # Αν υπάρχουν ακριβώς 2, προσθέτουμε 10 μονάδες.
        if number_of_rule_threats == 2:
            score += 10

        # Αν υπάρχουν 3 ή περισσότερα, προσθέτουμε 15 μονάδες.
        elif number_of_rule_threats >= 3:
            score += 15


        # ----------------------------------------
        # Specific dangerous combinations
        # ----------------------------------------

        # Αν υπάρχουν και:  Brute Force  +  Privilege Escalation προσθέτουμε 10.
        if (
            "Brute Force" in threats
            and "Privilege Escalation" in threats
        ):
            score += 10


        # Αν υπάρχουν και:  Brute Force  + Suspicious IP Activity προσθέτουμε 10.
        if (
            "Brute Force" in threats
            and "Suspicious IP Activity" in threats
        ):
            score += 10

        # Αν υπάρχουν και: Suspicious IP Activity  +  Privilege Escalation προσθέτουμε 10.
        if (
            "Suspicious IP Activity" in threats
            and "Privilege Escalation" in threats
        ):
            score += 10


        # ----------------------------------------
        # ML as supporting evidence
        # ----------------------------------------

        # Αν υπάρχει και ML Anomaly, προσθέτουμε 5 μονάδες.
        if "ML Anomaly" in threats:
            score += 5


        # ----------------------------------------
        # Limit score to 100
        # ----------------------------------------

        # Δεν επιτρέπουμε το score να ξεπεράσει το 100.
        incident["risk_score"] = min(score, 100)


        # ----------------------------------------
        # Severity
        # ----------------------------------------

        # Μετατρέπουμε το risk score σε severity.
        if incident["risk_score"] >= 80:
            incident["severity"] = "CRITICAL"

        elif incident["risk_score"] >= 60:
            incident["severity"] = "HIGH"

        elif incident["risk_score"] >= 30:
            incident["severity"] = "MEDIUM"

        else:
            incident["severity"] = "LOW"

    # Επιστρέφουμε όλα τα incidents μαζί με τα threats, το risk score και το severity.
    return incidents


def analyze_logs():
    logs = load_logs()

    brute_force_alerts = detect_brute_force(logs)
    unusual_login_alerts = detect_unusual_login(logs)
    privilege_alerts = detect_privilege_escalation(logs)
    suspicious_ip_alerts = detect_suspicious_ip(logs)
    anomaly_alerts = detect_anomalies(logs)

    all_alerts = (
        brute_force_alerts
        + unusual_login_alerts
        + privilege_alerts
        + suspicious_ip_alerts
        + anomaly_alerts
    )

    incidents = calculate_risk(all_alerts)

    return incidents

# MAIN
def main():
    print("Analyzing security logs...\n")

    incidents = analyze_logs()

    print("========== RISK ANALYSIS ==========\n")

    for incident in incidents.values():
        print(f"User: {incident['user']}")
        print(f"IP: {incident['ip']}")
        print(f"Threats: {', '.join(incident['threats'])}")
        print(f"Risk Score: {incident['risk_score']}/100")
        print(f"Severity: {incident['severity']}")
        print("-" * 40)

    print(f"Total incidents: {len(incidents)}")
    print()

    return incidents



if __name__ == "__main__":
    main()