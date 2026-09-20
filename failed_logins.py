import csv
from datetime import datetime, timedelta

LOG_FILE = "C:\\Users\\dionysia\\Desktop\\portofolio\\SentinelAI\\security_logs.csv"

def load_logs():
    logs = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
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

def get_failed_logins(logs):
    failed_logins = []
    


def main():

    logs = load_logs()

    get_failed_logins_list =  get_failed_logins(logs)
    


    if __name__ == "__main__":
        main()