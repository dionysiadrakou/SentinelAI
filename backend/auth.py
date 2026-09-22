from datetime import datetime, timedelta, timezone
import os
import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash

# Φορτώνουμε τις μεταβλητές από το αρχείο .env.
load_dotenv()

# ========================================================
# AUTHENTICATION CONFIGURATION
# ========================================================

# Secret key που χρησιμοποιείται για την υπογραφή
# των JWT tokens.
#
# Το πραγματικό secret βρίσκεται στο .env
# και δεν αποθηκεύεται μέσα στον κώδικα.
SECRET_KEY = os.getenv("SECRET_KEY")

# Ο αλγόριθμος που χρησιμοποιείται
# για την υπογραφή του JWT.
ALGORITHM = "HS256"

# Πόσο χρόνο παραμένει έγκυρο το JWT token.
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ========================================================
# PASSWORD HASHING
# ========================================================

# Δημιουργούμε PasswordHash object
# χρησιμοποιώντας τις ασφαλείς προεπιλογές
# του pwdlib.
password_hash = PasswordHash.recommended()


# ========================================================
# PASSWORD FUNCTIONS
# ========================================================

# Μετατρέπει ένα κανονικό password
# σε ασφαλές password hash.
def hash_password(password):
    return password_hash.hash(password)


# Ελέγχει αν ένα password αντιστοιχεί
# στο αποθηκευμένο password hash.
def verify_password(password, hashed_password):
    return password_hash.verify(
        password,
        hashed_password
    )


# ========================================================
# JWT TOKEN
# ========================================================

# Δημιουργεί ένα JWT token για έναν authenticated user.
def create_access_token(username):
    # Υπολογίζουμε πότε θα λήξει το token.
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    # Τα δεδομένα που αποθηκεύουμε μέσα στο token.
    payload = {
        "sub": username,
        "exp": expire
    }

    # Δημιουργούμε και επιστρέφουμε το JWT.
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    
# ========================================================
# TEST USER
# ========================================================

# Προσωρινός χρήστης για testing του authentication.
#
# Το password δεν αποθηκεύεται ως απλό κείμενο.
# Αποθηκεύουμε μόνο το ασφαλές hash του password.
TEST_USERNAME = "admin"
TEST_PASSWORD_HASH = hash_password("Sentinel123!")

# ========================================================
# GET CURRENT USER
# ========================================================

# Ελέγχει αν το JWT token που έστειλε ο χρήστης
# είναι έγκυρο και επιστρέφει το username.
def get_current_user(token):

    try:

        # Αποκωδικοποιούμε το JWT token
        # χρησιμοποιώντας το ίδιο secret key
        # και τον ίδιο αλγόριθμο που χρησιμοποιήσαμε
        # όταν δημιουργήσαμε το token.
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        # Παίρνουμε το username από το "sub"
        # που αποθηκεύσαμε μέσα στο JWT.
        username = payload.get("sub")

        # Αν δεν υπάρχει username,
        # το token δεν θεωρείται έγκυρο.
        if username is None:
            return None

        # Επιστρέφουμε τον username
        # του authenticated χρήστη.
        return username

    except jwt.InvalidTokenError:

        # Αν το token είναι λανθασμένο,
        # τροποποιημένο ή έχει λήξει,
        # επιστρέφουμε None.
        return None