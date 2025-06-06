import json, os, hashlib, base64
from getpass import getpass

USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hash_ = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(hash_).decode()

def add_user():
    username = input("Benutzername: ")
    password = getpass("Passwort (auch leer möglich): ")
    salt, hash_ = hash_password(password)

    users = load_users()
    users[username] = {"salt": salt, "hash": hash_}
    save_users(users)
    print(f"Nutzer '{username}' wurde gespeichert.")

if __name__ == "__main__":
    add_user()

