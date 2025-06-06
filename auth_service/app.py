from flask import Flask, request, render_template_string, redirect, url_for, session
import json, hashlib, base64, os

app = Flask(__name__)
app.secret_key = os.urandom(16)
USER_FILE = "users.json"

LOGIN_HTML = '''
<h2>Login</h2>
<form method="post">
  Benutzer: <input name="username"><br>
  Passwort: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
<p>{{ message }}</p>
'''

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=2)

def verify_password(username, password):
    users = load_users()
    user = users.get(username)
    if not user:
        return False
    salt = base64.b64decode(user["salt"])
    expected_hash = base64.b64decode(user["hash"])
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return test_hash == expected_hash

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hash_ = hashlib.pbkdf2_hmac("sha256", password, salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(hash_).decode()

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if verify_password(username, password):
            session["user"] = username
            return redirect(url_for("welcome"))
        else:
            message = "Login fehlgeschlagen."
    html_template = os.path.join(os.path.dirname(__file__), "html", "login.html")
    return render_template_string(LOGIN_HTML, message=message)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password", "").encode("utf-8")
        salt, hash_ = hash_password(password)

        users = load_users()

        if username in users:
            return "Benutzername bereits vorhanden.", 400

        users[username] = {"salt": salt, "hash": hash_}
        save_users(users)

        return f"Benutzer {username} erfolgreich registriert."

    return render_template_string("""
        <h2>Benutzer registrieren</h2>
        <form method="POST">
            Benutzername: <input name="username" required><br>
            Passwort: <input name="password" type="password"><br>
            <button type="submit">Registrieren</button>
        </form>
    """)


@app.route("/welcome")
def welcome():
    if "user" in session:
        return f"Willkommen, {session['user']}!"
    return redirect(url_for("login"))
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

