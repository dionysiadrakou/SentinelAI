# Ξεκίνα από μια μικρή Linux image που έχει Python 3.11.
FROM python:3.11-slim

# Ορίζουμε τον βασικό φάκελο εργασίας μέσα στο container.
WORKDIR /app

# Παίρνουμε τις Python dependencies.
COPY backend/requirements.txt .

# Εγκαθιστούμε: FastAPI, Uvicorn, psycopg, scikit-learn, PyJWT κτλ.
RUN pip install --no-cache-dir -r requirements.txt

# Παίρνουμε τον κώδικα του project μέσα στο image.
COPY . .

#Όταν ξεκινήσει το container, ξεκίνα το FastAPI.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]