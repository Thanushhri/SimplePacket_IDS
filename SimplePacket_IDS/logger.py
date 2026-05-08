from datetime import datetime

def log_alert(message):

    timestamp = datetime.now()

    with open("alerts.log", "a") as file:

        file.write(f"[{timestamp}] {message}\n")