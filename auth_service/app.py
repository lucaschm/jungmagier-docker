from flask import Flask, request, render_template_string, redirect, url_for, session
import json, hashlib, base64, os
import pyotp
import qrcode
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(16)
USER_FILE = "users.json"

LOGIN_HTML = '''
<h2>Login</h2>
<form method="post">
  Benutzer: <input name="username" required><br>
  Passwort: <input name="password" type="password"><br>
  2FA Code: <input name="totp_code" placeholder="6-stelliger Code"><br>
  <input type="submit" value="Login">
</form>
<p>{{ message }}</p>
<p><a href="/register">Neuen Benutzer registrieren</a></p>
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

def verify_totp(username, token):
    users = load_users()
    user = users.get(username)
    if not user or 'totp_secret' not in user:
        return False
    totp = pyotp.TOTP(user['totp_secret'])
    return totp.verify(token)

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
        totp_code = request.form.get("totp_code", "").strip()
        
        users = load_users()
        user = users.get(username)
        
        if not user:
            message = "Login fehlgeschlagen."
        else:
            # Prüfe ob Benutzer ein Passwort hat
            has_password = user.get("hash") and user.get("salt")
            has_2fa = 'totp_secret' in user
            
            password_valid = True
            if has_password:
                # Wenn Passwort gesetzt ist, muss es korrekt sein
                password_valid = verify_password(username, password)
            elif password:
                # Wenn kein Passwort gesetzt ist, aber eins eingegeben wurde
                message = "Dieser Benutzer hat kein Passwort. 2FA Code genügt."
                password_valid = False
            
            if password_valid:
                if has_2fa:
                    if totp_code:
                        # Verifiziere 2FA Code
                        if verify_totp(username, totp_code):
                            session["user"] = username
                            return redirect(url_for("welcome"))
                        else:
                            message = "Ungültiger 2FA Code."
                    else:
                        if has_password:
                            message = "2FA Code erforderlich für diesen Benutzer."
                        else:
                            message = "2FA Code ist zwingend erforderlich (kein Passwort gesetzt)."
                elif has_password:
                    # Nur Passwort, kein 2FA - normaler Login
                    session["user"] = username
                    return redirect(url_for("welcome"))
                else:
                    # Weder Passwort noch 2FA - das sollte nicht passieren
                    message = "Benutzer hat weder Passwort noch 2FA. Bitte kontaktieren Sie den Administrator."
            else:
                if not message:  # Falls noch keine spezifische Nachricht gesetzt
                    message = "Login fehlgeschlagen."
    
    return render_template_string(LOGIN_HTML, message=message)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password", "").strip()

        users = load_users()

        if username in users:
            return "Benutzername bereits vorhanden.", 400

        user_data = {}
        
        if password:
            # Passwort wurde eingegeben - hashen und speichern
            salt, hash_ = hash_password(password.encode("utf-8"))
            user_data = {"salt": salt, "hash": hash_}
            message = f"Benutzer {username} mit Passwort registriert."
        else:
            # Kein Passwort - 2FA wird zwingend erforderlich
            message = f"Benutzer {username} ohne Passwort registriert - 2FA ist zwingend erforderlich!"
        
        users[username] = user_data
        save_users(users)

        return f"{message} <a href='/setup-2fa/{username}'>2FA einrichten</a>"

    return render_template_string("""
        <h2>Benutzer registrieren</h2>
        <form method="POST">
            Benutzername: <input name="username" required><br>
            Passwort: <input name="password" type="password" placeholder="Optional"><br>
            <button type="submit">Registrieren</button>
        </form>
        <p><a href="/">Zurück zum Login</a></p>
    """)

@app.route("/setup-2fa/<username>", methods=["GET", "POST"])
def setup_2fa(username):
    users = load_users()
    if username not in users:
        return "Benutzer nicht gefunden.", 404
    
    if request.method == "POST":
        totp_code = request.form.get("totp_code")
        secret = session.get(f"temp_secret_{username}")
        
        if not secret:
            return "Fehler: Kein temporäres Secret gefunden. Bitte beginnen Sie erneut.", 400
        
        totp = pyotp.TOTP(secret)
        if totp.verify(totp_code):
            # 2FA Code korrekt - Secret dauerhaft speichern
            users[username]["totp_secret"] = secret
            save_users(users)
            session.pop(f"temp_secret_{username}", None)
            return f"2FA erfolgreich für {username} eingerichtet! <a href='/'>Zum Login</a>"
        else:
            return "Ungültiger 2FA Code. Bitte versuchen Sie es erneut."
    
    # Generiere neues Secret
    secret = pyotp.random_base32()
    session[f"temp_secret_{username}"] = secret
    
    # Erstelle QR Code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="HAW IT-Security Lab"
    )
    
    return render_template_string("""
        <h2>2FA Einrichtung für {{ username }}</h2>
        <p>1. Scannen Sie diesen QR-Code mit Google Authenticator:</p>
        <img src="/qr/{{ username }}" alt="QR Code">
        <p>2. Oder geben Sie diesen Secret manuell ein: <code>{{ secret }}</code></p>
        <p>3. Geben Sie den 6-stelligen Code aus Ihrer App ein:</p>
        <form method="POST">
            <input name="totp_code" placeholder="6-stelliger Code" required><br>
            <button type="submit">2FA aktivieren</button>
        </form>
    """, username=username, secret=secret)

@app.route("/qr/<username>")
def qr_code(username):
    secret = session.get(f"temp_secret_{username}")
    if not secret:
        return "QR Code nicht verfügbar", 404
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="HAW IT-Security Lab"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    from flask import Response
    return Response(img_io.getvalue(), mimetype='image/png')

@app.route("/welcome")
def welcome():
    if "user" in session:
        return f"""
        <h2>Willkommen, {session['user']}!</h2>
        <p>Sie sind erfolgreich eingeloggt.</p>
        <p><a href="/logout">Logout</a></p>
        """
    return redirect(url_for("login"))

@app.route("/logout")  
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

