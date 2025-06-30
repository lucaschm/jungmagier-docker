from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import json, hashlib, base64, os
import pyotp
import qrcode
from io import BytesIO
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference, AuthenticatorAttachment
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import uuid
import time
import secrets
import cryptography


app = Flask(__name__)
app.secret_key = os.urandom(16)
USER_FILE = "users.json"

# WebAuthn configuration
RP_ID = "merkur"  # Domain name 
RP_NAME = "HAW IT-Security Lab"
ORIGIN = "https://auth.merkur"  # origin

# Implicit Login configuration
implicit_sessions = {}  # Stores active implicit login sessions

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
<p><a href="/passkey-login">Mit Passkey anmelden</a></p>
<p><a href="/implicit-login">Impliziter Login (ohne Passwort-Übertragung)</a></p>
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


def encrypt_aes(plaintext, key_b64):
    """AES-GCM encryption"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Use first 32 bytes of PBKDF2 (Password-Based Key Derivation Function 2) hash as AES-256 key
        key_bytes = base64.b64decode(key_b64)[:32]
        
        # Generate random nonce (96 bits for GCM)
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key_bytes)
        
        # Encrypt with authentication
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Combine nonce + ciphertext for transmission
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()
        
    except Exception as e:
        print(f"AES encryption error: {e}")
        return None

def decrypt_aes(ciphertext_b64, key_b64):
    """AES-GCM decryption"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Use first 32 bytes of PBKDF2 hash as AES-256 key
        key_bytes = base64.b64decode(key_b64)[:32]
        
        # Decode combined data
        combined = base64.b64decode(ciphertext_b64)
        
        # Split nonce (first 12 bytes) and ciphertext
        nonce = combined[:12]
        ciphertext = combined[12:]
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key_bytes)
        
        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
        
    except Exception as e:
        print(f"AES decryption error: {e}")
        return None

def encrypt_with_session_key(plaintext, session_key):
    """Encrypt with session key (base64 encoded)"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Decode session key and ensure 32 bytes for AES-256
        key_bytes = base64.urlsafe_b64decode(session_key + '==')[:32]
        
        # Generate random nonce (96 bits for GCM)
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key_bytes)
        
        # Encrypt with authentication
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Combine nonce + ciphertext for transmission
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()
        
    except Exception as e:
        print(f"Session key encryption error: {e}")
        return None

def decrypt_with_session_key(ciphertext_b64, session_key):
    """Decrypt with session key"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Decode session key and ensure 32 bytes for AES-256
        key_bytes = base64.urlsafe_b64decode(session_key + '==')[:32]
        
        # Decode combined data
        combined = base64.b64decode(ciphertext_b64)
        
        # Split nonce (first 12 bytes) and ciphertext
        nonce = combined[:12]
        ciphertext = combined[12:]
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key_bytes)
        
        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
        
    except Exception as e:
        print(f"Session key decryption error: {e}")
        return None

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

        return f"""{message} 
        <p><a href='/setup-2fa/{username}'>2FA einrichten</a></p>
        <p><a href='/register-passkey'>Passkey registrieren</a></p>
        <p><a href='/'>Zum Login</a></p>"""

    return render_template_string("""
        <h2>Benutzer registrieren</h2>
        <form method="POST">
            Benutzername: <input name="username" required><br>
            Passwort: <input name="password" type="password" placeholder="Optional"><br>
            <button type="submit">Registrieren</button>
        </form>
        <p><a href="/register-passkey">Oder direkt Passkey registrieren</a></p>
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
        users = load_users()
        user = users.get(session['user'], {})
        
        # Check what authentication methods are available
        has_password = 'hash' in user and 'salt' in user
        has_2fa = 'totp_secret' in user
        has_passkey = 'passkeys' in user and len(user['passkeys']) > 0
        
        return f"""
        <h2>Willkommen, {session['user']}!</h2>
        <p>Sie sind erfolgreich eingeloggt.</p>
        
        <h3>Ihre Authentifizierungsmethoden:</h3>
        <ul>
            <li>Passwort: {'✓' if has_password else '✗'}</li>
            <li>2FA (TOTP): {'✓' if has_2fa else '✗'}</li>
            <li>Passkey: {'✓' if has_passkey else '✗'} {f'({len(user.get("passkeys", []))} registriert)' if has_passkey else ''}</li>
        </ul>
        
        <p><a href="/setup-2fa/{session['user']}">2FA einrichten/ändern</a></p>
        <p><a href="/register-passkey">Neuen Passkey registrieren</a></p>
        <p><a href="/logout">Logout</a></p>
        """
#
#     return redirect(url_for("login"))

@app.route("/logout")  
def logout():
    session.clear()
    return redirect(url_for("login"))

# Implicit Login Routes
@app.route("/implicit-login")
def implicit_login_page():
    return render_template_string("""
        <h2>Impliziter Login</h2>
        
        <div id="step1">
            <h3>Schritt 1: Benutzer</h3>
            <input id="username" placeholder="Benutzername"><br><br>
            <button onclick="loadUser()">Weiter</button>
        </div>
        
        <div id="step2" style="display:none;">
            <h3>Schritt 2: Shared Key</h3>
            <p>Salt: <span id="saltDisplay"></span></p>
            
            <h4>Option A: Passwort hashen</h4>
            <input id="password" type="password" placeholder="Passwort"><br><br>
            <button onclick="hashPassword()">Hash berechnen</button>
            
            <div id="hashResult" style="display:none;">
                <p>🔐 PBKDF2-Hash: <code id="clientHashDisplay"></code></p>
                <p>🔒 Verschlüsselung: AES-256-GCM</p>
            </div>
            
            <h4>Option B: Hash direkt eingeben</h4>
            <textarea id="directHashInput" placeholder="Shared Key eingeben..."></textarea><br><br>
            <button onclick="useDirectHash()">Verwenden</button>
        </div>
        
        <div id="step3" style="display:none;">
            <h3>Schritt 3: Login</h3>
            <textarea id="sharedKeyInput" placeholder="Shared Key"></textarea><br><br>
            <button onclick="verifyHashAndLogin()">Login starten</button>
            
            <div id="hashComparison" style="display:none;">
                <p>Client: <code id="clientHashComp"></code></p>
                <p>Server: <code id="serverHashComp"></code></p>
                <p id="hashMatchResult"></p>
            </div>
        </div>
        
        <div id="step4" style="display:none;">
            <h3>🎉 Login erfolgreich</h3>
            
            <p>Client Nonce: <span id="clientNonceEcho"></span></p>
            <p>Server Nonce: <span id="serverNonce"></span></p>
            <p>Session ID: <span id="sessionIdDisplay"></span></p>
            
            <h4>💬 Nachrichten</h4>
            <input id="message" placeholder="Nachricht"><br><br>
            <button onclick="sendMessage()">Senden</button>
            <div id="response"></div>
            
            <h4>📊 Session Status</h4>
            <button onclick="checkSessionStatus()">Session prüfen</button>
            <div id="sessionStatus"></div>
        </div>
        
        <div id="messages"></div>
        <p><a href="/">Zurück zum normalen Login</a></p>
        
        <script>
        let currentUsername = '';
        let currentSalt = '';
        let currentClientHash = '';
        let sessionId = '';
        let currentSessionKey = '';
        
        async function loadUser() {
            currentUsername = document.getElementById('username').value;
            if (!currentUsername) {
                alert('Benutzername erforderlich');
                return;
            }
            
            try {
                document.getElementById('messages').innerHTML = '<p>Lade Benutzer...</p>';
                
                const saltResponse = await fetch('/get-salt/' + currentUsername);
                if (!saltResponse.ok) {
                    throw new Error('Benutzer nicht gefunden');
                }
                const {salt} = await saltResponse.json();
                currentSalt = salt;
                
                document.getElementById('saltDisplay').textContent = salt;
                document.getElementById('step1').style.display = 'none';
                document.getElementById('step2').style.display = 'block';
                document.getElementById('messages').innerHTML = '<p>✅ Benutzer geladen</p>';
                
            } catch (error) {
                document.getElementById('messages').innerHTML = '<p>❌ ' + error.message + '</p>';
            }
        }
        
        async function hashPassword() {
            const password = document.getElementById('password').value;
            if (!password) {
                alert('Passwort erforderlich');
                return;
            }
            
            try {
                document.getElementById('messages').innerHTML += '<p>Berechne Hash...</p>';
                
                const sharedKey = await deriveSharedKey(password, currentSalt);
                currentClientHash = sharedKey;
                
                document.getElementById('clientHashDisplay').textContent = sharedKey;
                document.getElementById('hashResult').style.display = 'block';
                document.getElementById('step2').style.display = 'none';
                document.getElementById('step3').style.display = 'block';
                
                // Auto-fill the hash in the textarea
                document.getElementById('sharedKeyInput').value = sharedKey;
                
                document.getElementById('messages').innerHTML += '<p>✅ Hash berechnet</p>';
                
            } catch (error) {
                document.getElementById('messages').innerHTML += '<p>❌ ' + error.message + '</p>';
            }
        }
        
        async function useDirectHash() {
            const directHash = document.getElementById('directHashInput').value.trim();
            if (!directHash) {
                alert('Shared Key erforderlich');
                return;
            }
            
            try {
                currentClientHash = directHash;
                
                document.getElementById('step2').style.display = 'none';
                document.getElementById('step3').style.display = 'block';
                
                // Auto-fill the hash in the textarea
                document.getElementById('sharedKeyInput').value = directHash;
                
                document.getElementById('messages').innerHTML += '<p>✅ Shared Key übernommen</p>';
                
            } catch (error) {
                document.getElementById('messages').innerHTML += '<p style="color:red;">❌ Fehler: ' + error.message + '</p>';
            }
        }
        
        async function verifyHashAndLogin() {
            const inputHash = document.getElementById('sharedKeyInput').value.trim();
            if (!inputHash) {
                alert('Bitte Hash eingeben');
                return;
            }
            
            try {
                // 1. Hash-Vergleich anzeigen
                document.getElementById('hashComparison').style.display = 'block';
                document.getElementById('clientHashComp').textContent = inputHash;
                
                // Get server hash for comparison
                const usersResponse = await fetch('/get-user-hash/' + currentUsername);
                let serverHash = '';
                let hashMatch = false;
                
                if (usersResponse.ok) {
                    const userData = await usersResponse.json();
                    serverHash = userData.hash;
                    document.getElementById('serverHashComp').textContent = serverHash;
                    
                    hashMatch = (inputHash === serverHash);
                    
                    if (hashMatch) {
                        document.getElementById('hashMatchResult').innerHTML = '<p>✅ Hash stimmt überein</p>';
                    } else {
                        document.getElementById('hashMatchResult').innerHTML = '<p>❌ Hash stimmt nicht überein</p>';
                        return;
                    }
                }
                
                // 2. Implicit Login starten
                document.getElementById('messages').innerHTML += '<p>Starte Login...</p>';
                
                const clientNonce = Date.now().toString();
                const encryptedNonce = await encryptWithKey(clientNonce, inputHash);
                
                const response = await fetch('/implicit-login/challenge', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: currentUsername,
                        encrypted_nonce: encryptedNonce
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    // Decrypt server response (XOR is symmetric, so we use the same function)
                    const encryptedBase64 = result.encrypted_response;
                    console.log('Encrypted response from server:', encryptedBase64);
                    
                    // Decrypt: XOR the base64-decoded data with our key
                    const decryptedResponse = await decryptWithKey(encryptedBase64, inputHash);
                    console.log('Decrypted response:', decryptedResponse);
                    
                    const responseData = JSON.parse(decryptedResponse);
                    
                    // Verify client nonce
                    if (responseData.client_nonce !== clientNonce) {
                        throw new Error('Server nonce verification failed');
                    }
                    
                    sessionId = responseData.session_id;
                    currentSessionKey = responseData.session_key;
                    
                    // Show success
                    document.getElementById('step3').style.display = 'none';
                    document.getElementById('step4').style.display = 'block';
                    
                    // Show server response details
                    document.getElementById('clientNonceEcho').textContent = responseData.client_nonce;
                    document.getElementById('serverNonce').textContent = responseData.server_nonce;
                    document.getElementById('sessionIdDisplay').textContent = responseData.session_id;
                    
                    document.getElementById('messages').innerHTML += '<p>🎉 Login erfolgreich</p>';
                } else {
                    document.getElementById('messages').innerHTML += '<p>❌ Login fehlgeschlagen: ' + result.error + '</p>';
                }
                
            } catch (error) {
                document.getElementById('messages').innerHTML += '<p>❌ ' + error.message + '</p>';
            }
        }
        
        async function sendMessage() {
            const message = document.getElementById('message').value;
            if (!message) {
                alert('Nachricht erforderlich');
                return;
            }
            
            try {
                // Get session key from stored session data
                const sessionKey = currentSessionKey;
                if (!sessionKey) {
                    document.getElementById('response').innerHTML = '<p>❌ Session Key nicht verfügbar</p>';
                    return;
                }
                
                // Encrypt message with session key
                const encryptedMessage = await encryptWithSessionKey(message, sessionKey);
                
                const response = await fetch('/implicit-login/message', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: sessionId,
                        encrypted_message: encryptedMessage
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    // Decrypt server response
                    const decryptedResponse = await decryptWithSessionKey(result.encrypted_response, sessionKey);
                    document.getElementById('response').innerHTML = '<p>Server: ' + decryptedResponse + '</p>';
                    document.getElementById('message').value = '';
                } else {
                    document.getElementById('response').innerHTML = '<p>❌ ' + result.error + '</p>';
                }
                
            } catch (error) {
                document.getElementById('response').innerHTML = '<p>❌ ' + error.message + '</p>';
            }
        }
        
        async function checkSessionStatus() {
            try {
                const response = await fetch('/implicit-login/status');
                const result = await response.json();
                
                let statusHtml = '<p>Aktive Sessions: ' + result.active_sessions + '</p>';
                
                if (result.sessions.length > 0) {
                    statusHtml += '<ul>';
                    result.sessions.forEach(session => {
                        const isOwnSession = (session.session_id === sessionId);
                        statusHtml += '<li>' + 
                            (isOwnSession ? '<strong>' : '') +
                            session.username + ' (' + session.session_id.substring(0, 8) + '...) - ' +
                            'Alter: ' + session.age_seconds + 's, ' +
                            'Läuft ab in: ' + session.expires_in + 's' +
                            (isOwnSession ? ' [DEINE SESSION]</strong>' : '') +
                            '</li>';
                    });
                    statusHtml += '</ul>';
                }
                
                document.getElementById('sessionStatus').innerHTML = statusHtml;
                
            } catch (error) {
                document.getElementById('sessionStatus').innerHTML = '<p>❌ ' + error.message + '</p>';
            }
        }
        
        // Crypto functions for client-side hashing
        async function deriveSharedKey(password, salt) {
            // Convert salt from base64
            const saltBytes = base64ToArrayBuffer(salt);
            const passwordBytes = new TextEncoder().encode(password);
            
            // Import password as key material
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                passwordBytes,
                'PBKDF2',
                false,
                ['deriveBits']
            );
            
            // Derive key using same parameters as server
            const derivedBits = await crypto.subtle.deriveBits({
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: 100000,  // Same as server
                hash: 'SHA-256'
            }, keyMaterial, 256);  // 32 bytes = 256 bits
            
            // Convert to base64 for consistency with server
            return arrayBufferToBase64(derivedBits);
        }
        
        async function encryptWithKey(plaintext, keyBase64) {
            // AES-GCM encryption using Web Crypto API
            try {
                // Decode base64 key and use first 32 bytes for AES-256
                const keyBytes = base64ToUint8Array(keyBase64).slice(0, 32);
                
                // Import key for AES-GCM
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'AES-GCM' },
                    false,
                    ['encrypt']
                );
                
                // Generate random IV (96 bits for GCM)
                const iv = crypto.getRandomValues(new Uint8Array(12));
                
                // Convert plaintext to bytes
                const textBytes = new TextEncoder().encode(plaintext);
                
                // Encrypt with AES-GCM
                const encrypted = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    cryptoKey,
                    textBytes
                );
                
                // Combine IV + encrypted data
                const combined = new Uint8Array(iv.length + encrypted.byteLength);
                combined.set(iv, 0);
                combined.set(new Uint8Array(encrypted), iv.length);
                
                // Convert to base64
                return uint8ArrayToBase64(combined);
                
            } catch (error) {
                console.error('AES encryption error:', error);
                throw new Error('AES-Verschlüsselung fehlgeschlagen');
            }
        }
        
        function base64ToUint8Array(base64) {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }
        
        function uint8ArrayToBase64(bytes) {
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        
        async function decryptWithKey(ciphertextBase64, keyBase64) {
            // AES-GCM decryption using Web Crypto API
            try {
                // Decode base64 key and use first 32 bytes for AES-256
                const keyBytes = base64ToUint8Array(keyBase64).slice(0, 32);
                
                // Import key for AES-GCM
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt']
                );
                
                // Decode combined data
                const combined = base64ToUint8Array(ciphertextBase64);
                
                // Split IV (first 12 bytes) and ciphertext
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);
                
                // Decrypt with AES-GCM
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    cryptoKey,
                    ciphertext
                );
                
                // Convert back to string
                return new TextDecoder().decode(decrypted);
                
            } catch (error) {
                console.error('AES decryption error:', error);
                throw new Error('AES-Entschlüsselung fehlgeschlagen');
            }
        }
        
        function base64ToArrayBuffer(base64) {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        
        async function encryptWithSessionKey(plaintext, sessionKey) {
            // Session key encryption using Web Crypto API (AES-GCM)
            try {
                // Decode session key (URL-safe base64) and use first 32 bytes for AES-256
                const keyBytes = base64UrlToUint8Array(sessionKey).slice(0, 32);
                
                // Import key for AES-GCM
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'AES-GCM' },
                    false,
                    ['encrypt']
                );
                
                // Generate random IV (96 bits for GCM)
                const iv = crypto.getRandomValues(new Uint8Array(12));
                
                // Convert plaintext to bytes
                const textBytes = new TextEncoder().encode(plaintext);
                
                // Encrypt with AES-GCM
                const encrypted = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    cryptoKey,
                    textBytes
                );
                
                // Combine IV + encrypted data
                const combined = new Uint8Array(iv.length + encrypted.byteLength);
                combined.set(iv, 0);
                combined.set(new Uint8Array(encrypted), iv.length);
                
                // Convert to base64
                return uint8ArrayToBase64(combined);
                
            } catch (error) {
                console.error('Session key encryption error:', error);
                throw new Error('Session Key Verschlüsselung fehlgeschlagen');
            }
        }
        
        async function decryptWithSessionKey(ciphertextBase64, sessionKey) {
            // Session key decryption using Web Crypto API (AES-GCM)
            try {
                // Decode session key (URL-safe base64) and use first 32 bytes for AES-256
                const keyBytes = base64UrlToUint8Array(sessionKey).slice(0, 32);
                
                // Import key for AES-GCM
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt']
                );
                
                // Decode combined data
                const combined = base64ToUint8Array(ciphertextBase64);
                
                // Split IV (first 12 bytes) and ciphertext
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);
                
                // Decrypt with AES-GCM
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    cryptoKey,
                    ciphertext
                );
                
                // Convert back to string
                return new TextDecoder().decode(decrypted);
                
            } catch (error) {
                console.error('Session key decryption error:', error);
                throw new Error('Session Key Entschlüsselung fehlgeschlagen');
            }
        }
        
        function base64UrlToUint8Array(base64Url) {
            // Convert URL-safe Base64 to standard Base64
            let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            while (base64.length % 4) {
                base64 += '=';
            }
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }
        </script>
    """)

@app.route("/get-salt/<username>")
def get_salt(username):
    """Get user's salt for client-side hashing"""
    users = load_users()
    user = users.get(username)
    if not user or 'salt' not in user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"salt": user["salt"]})

@app.route("/get-user-hash/<username>")
def get_user_hash(username):
    """Get user's hash for comparison"""
    users = load_users()
    user = users.get(username)
    if not user or 'hash' not in user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"hash": user["hash"]})

@app.route("/implicit-login/challenge", methods=["POST"])
def implicit_login_challenge():
    """
    Schritt 1+2 des Protokolls:
    1. Client → Server: username, encrypted_nonce
    2. Server → Client: encrypted_response (mit client_nonce, server_nonce, session_id, session_key)
    """
    try:
        data = request.get_json()
        username = data.get('username')
        encrypted_nonce = data.get('encrypted_nonce')
        
        if not all([username, encrypted_nonce]):
            return jsonify({"success": False, "error": "Missing data"})
        
        # Verify user exists and has password
        users = load_users()
        user = users.get(username)
        if not user or 'hash' not in user:
            return jsonify({"success": False, "error": "User not found or no password set"})
        
        # Get shared key from user's password hash
        shared_key_b64 = user['hash']  # This is the shared secret
        
        # Decrypt client nonce (AES-GCM)
        client_nonce = decrypt_aes(encrypted_nonce, shared_key_b64)
        if client_nonce is None:
            return jsonify({"success": False, "error": "Invalid encryption or authentication failed"})
        
        # Generate server nonce and session data
        server_nonce = str(int(time.time() * 1000))
        session_id = secrets.token_urlsafe(16)
        session_key = secrets.token_urlsafe(32)
        
        # Create response payload
        response_payload = {
            "client_nonce": client_nonce,    # Proof server could decrypt
            "server_nonce": server_nonce,
            "session_id": session_id,
            "session_key": session_key
        }
        
        # Encrypt response with shared key (AES-GCM)
        encrypted_response = encrypt_aes(json.dumps(response_payload), shared_key_b64)
        if encrypted_response is None:
            return jsonify({"success": False, "error": "AES encryption failed"})
        
        # Store session
        implicit_sessions[session_id] = {
            "username": username,
            "session_key": session_key,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "created_at": time.time()
        }
        
        # Return only encrypted data
        return jsonify({
            "success": True,
            "encrypted_response": encrypted_response
        })
        
    except Exception as e:
        print(f"Error in implicit login challenge: {e}")
        return jsonify({"success": False, "error": "Authentication failed"})

@app.route("/implicit-login/message", methods=["POST"])
def implicit_login_message():
    """
    Schritt 3+4 des Protokolls:
    Verschlüsselte Kommunikation mit Session-Key
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        encrypted_message = data.get('encrypted_message')
        
        if not all([session_id, encrypted_message]):
            return jsonify({"success": False, "error": "Missing data"})
        
        # Get session
        session_data = implicit_sessions.get(session_id)
        if not session_data:
            return jsonify({"success": False, "error": "Invalid session"})
        
        # Check session age (5 minutes max)
        if time.time() - session_data['created_at'] > 300:
            del implicit_sessions[session_id]
            return jsonify({"success": False, "error": "Session expired"})
        
        # Decrypt message with session key
        message = decrypt_with_session_key(encrypted_message, session_data['session_key'])
        if message is None:
            return jsonify({"success": False, "error": "Message decryption failed"})
        
        # Process message (echo back with timestamp)
        response_message = f"Echo von {session_data['username']}: {message} (um {time.strftime('%H:%M:%S')})"
        
        # Encrypt response with session key
        encrypted_response = encrypt_with_session_key(response_message, session_data['session_key'])
        if encrypted_response is None:
            return jsonify({"success": False, "error": "Response encryption failed"})
        
        return jsonify({
            "success": True,
            "encrypted_response": encrypted_response
        })
        
    except Exception as e:
        print(f"Error in implicit login message: {e}")
        return jsonify({"success": False, "error": "Message processing failed"})

@app.route("/implicit-login/status", methods=["GET"])
def implicit_login_status():
    """Debug: Zeige aktive Sessions"""
    active_sessions = []
    current_time = time.time()
    
    for session_id, session_data in list(implicit_sessions.items()):
        age = current_time - session_data['created_at']
        if age > 300:  # 5 minutes
            del implicit_sessions[session_id]
        else:
            active_sessions.append({
                "session_id": session_id,
                "username": session_data['username'],
                "age_seconds": int(age),
                "expires_in": int(300 - age)
            })
    
    return jsonify({
        "active_sessions": len(active_sessions),
        "sessions": active_sessions
    })

# Passkey Routes
@app.route("/register-passkey", methods=["GET", "POST"])
def register_passkey():
    if request.method == "GET":
        return render_template_string("""
            <h2>Passkey Registrierung</h2>
            <form id="registerForm">
                Benutzername: <input id="username" required><br><br>
                <button type="button" onclick="registerPasskey()">Passkey registrieren</button>
            </form>
            <div id="message"></div>
            <p><a href="/">Zurück zum Login</a></p>
            
            <script>
            async function registerPasskey() {
                const username = document.getElementById('username').value;
                if (!username) {
                    document.getElementById('message').innerHTML = '<p style="color: red;">Benutzername erforderlich</p>';
                    return;
                }
                
                try {
                    // Get registration options from server
                    const optionsResponse = await fetch('/passkey/register/begin', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username: username})
                    });
                    
                    if (!optionsResponse.ok) {
                        throw new Error('Failed to get registration options');
                    }
                    
                    const options = await optionsResponse.json();
                    
                    // Convert base64 to ArrayBuffer for challenge and user.id
                    options.challenge = base64ToArrayBuffer(options.challenge);
                    options.user.id = base64ToArrayBuffer(options.user.id);
                    
                    // Create credential
                    const credential = await navigator.credentials.create({
                        publicKey: options
                    });
                    
                    // Convert ArrayBuffer to base64 for transmission
                    const credentialForServer = {
                        id: credential.id,
                        rawId: arrayBufferToBase64(credential.rawId),
                        response: {
                            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
                            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
                        },
                        type: credential.type
                    };
                    
                    // Send credential to server
                    const registerResponse = await fetch('/passkey/register/complete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            username: username,
                            credential: credentialForServer
                        })
                    });
                    
                    const result = await registerResponse.json();
                    if (result.success) {
                        document.getElementById('message').innerHTML = '<p style="color: green;">Passkey erfolgreich registriert! <a href="/">Zum Login</a></p>';
                    } else {
                        document.getElementById('message').innerHTML = '<p style="color: red;">Registrierung fehlgeschlagen: ' + result.error + '</p>';
                    }
                    
                } catch (error) {
                    console.error('Error:', error);
                    document.getElementById('message').innerHTML = '<p style="color: red;">Fehler: ' + error.message + '</p>';
                }
            }
            
            function base64ToArrayBuffer(base64) {
                // Convert URL-safe Base64 to standard Base64
                base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
                // Add padding if needed
                while (base64.length % 4) {
                    base64 += '=';
                }
                const binaryString = atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes.buffer;
            }
            
            function arrayBufferToBase64(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary);
            }
            </script>
        """)

@app.route("/passkey-login")
def passkey_login():
    return render_template_string("""
        <h2>Passkey Login</h2>
        <button onclick="loginWithPasskey()">Mit Passkey anmelden</button>
        <div id="message"></div>
        <p><a href="/">Zurück zum normalen Login</a></p>
        
        <script>
        async function loginWithPasskey() {
            try {
                // Get authentication options from server
                const optionsResponse = await fetch('/passkey/authenticate/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                
                if (!optionsResponse.ok) {
                    throw new Error('Failed to get authentication options');
                }
                
                const options = await optionsResponse.json();
                
                // Convert base64 to ArrayBuffer
                options.challenge = base64ToArrayBuffer(options.challenge);
                if (options.allowCredentials) {
                    options.allowCredentials.forEach(cred => {
                        cred.id = base64ToArrayBuffer(cred.id);
                    });
                }
                
                // Get credential
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                // Convert ArrayBuffer to base64 for transmission
                const credentialForServer = {
                    id: credential.id,
                    rawId: arrayBufferToBase64(credential.rawId),
                    response: {
                        authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                        signature: arrayBufferToBase64(credential.response.signature),
                        userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
                    },
                    type: credential.type
                };
                
                // Send credential to server
                const authResponse = await fetch('/passkey/authenticate/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        credential: credentialForServer
                    })
                });
                
                const result = await authResponse.json();
                if (result.success) {
                    window.location.href = '/welcome';
                } else {
                    document.getElementById('message').innerHTML = '<p style="color: red;">Authentifizierung fehlgeschlagen: ' + result.error + '</p>';
                }
                
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('message').innerHTML = '<p style="color: red;">Fehler: ' + error.message + '</p>';
            }
        }
        
        function base64ToArrayBuffer(base64) {
            // Convert URL-safe Base64 to standard Base64
            base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            while (base64.length % 4) {
                base64 += '=';
            }
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        </script>
    """)

@app.route("/passkey/register/begin", methods=["POST"])
def passkey_register_begin():
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({"error": "Username required"}), 400
        
        users = load_users()
        if username not in users:
            # Create user if not exists
            users[username] = {}
            save_users(users)
        
        # Generate user ID
        user_id = username
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            user_display_name=username,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            attestation=AttestationConveyancePreference.DIRECT
        )
        
        # Store challenge in session
        session[f"challenge_{username}"] = base64.b64encode(options.challenge).decode()
        
        # Convert options to dict for JSON response
        options_dict = {
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"id": options.rp.id, "name": options.rp.name},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [{"alg": param.alg, "type": param.type} for param in options.pub_key_cred_params],
            "timeout": options.timeout,
            "attestation": options.attestation,
            "authenticatorSelection": {
                "authenticatorAttachment": options.authenticator_selection.authenticator_attachment,
                "userVerification": options.authenticator_selection.user_verification
            }
        }
        
        print(f"DEBUG: Generated options for user {username}")
        return jsonify(options_dict)
        
    except Exception as e:
        print(f"ERROR in passkey_register_begin: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/passkey/register/complete", methods=["POST"])
def passkey_register_complete():
    try:
        data = request.get_json()
        username = data.get('username')
        credential = data.get('credential')
        
        print(f"DEBUG: Completing registration for {username}")
        
        if not username or not credential:
            return jsonify({"success": False, "error": "Missing data"}), 400
        
        # Get challenge from session
        challenge_b64 = session.get(f"challenge_{username}")
        if not challenge_b64:
            return jsonify({"success": False, "error": "No challenge found"}), 400
        
        challenge = base64.b64decode(challenge_b64)
        
        # Verify registration
        verification = verify_registration_response(
            credential={
                "id": credential["id"],
                "rawId": credential["rawId"],
                "response": {
                    "attestationObject": credential["response"]["attestationObject"],
                    "clientDataJSON": credential["response"]["clientDataJSON"]
                },
                "type": credential["type"]
            },
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
        
        print(f"DEBUG: Verification result: {verification}")
        
        if verification:
            # Store credential
            users = load_users()
            if 'passkeys' not in users[username]:
                users[username]['passkeys'] = []
            
            # Convert bytes to base64 strings for JSON storage
            public_key_b64 = base64.b64encode(verification.credential_public_key).decode()
            
            users[username]['passkeys'].append({
                "id": credential["id"],
                "public_key": public_key_b64,
                "sign_count": verification.sign_count,
                "created_at": str(uuid.uuid4())
            })
            save_users(users)
            
            # Clean up session
            session.pop(f"challenge_{username}", None)
            
            print(f"DEBUG: Successfully registered passkey for {username}")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Verification failed"})
            
    except Exception as e:
        print(f"ERROR in passkey_register_complete: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)})

@app.route("/passkey/authenticate/begin", methods=["POST"])
def passkey_authenticate_begin():
    try:
        print("DEBUG: Starting authentication")
        
        # Get all registered credentials
        users = load_users()
        allow_credentials = []
        
        for username, user_data in users.items():
            if 'passkeys' in user_data:
                for passkey in user_data['passkeys']:
                    allow_credentials.append({
                        "id": passkey["id"],  # Keep as base64 string
                        "type": "public-key"
                    })
        
        print(f"DEBUG: Found {len(allow_credentials)} credentials")
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            user_verification=UserVerificationRequirement.PREFERRED
        )
        
        # Store challenge in session
        session["auth_challenge"] = base64.b64encode(options.challenge).decode()
        
        # Convert options to dict for JSON response
        options_dict = {
            "challenge": base64.b64encode(options.challenge).decode(),
            "timeout": options.timeout,
            "rpId": options.rp_id,
            "allowCredentials": [{"id": cred["id"], "type": cred["type"]} for cred in allow_credentials],  # Use IDs as strings
            "userVerification": options.user_verification
        }
        
        print("DEBUG: Generated authentication options")
        return jsonify(options_dict)
        
    except Exception as e:
        print(f"ERROR in passkey_authenticate_begin: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/passkey/authenticate/complete", methods=["POST"])
def passkey_authenticate_complete():
    try:
        data = request.get_json()
        credential = data.get('credential')
        
        if not credential:
            return jsonify({"success": False, "error": "Missing credential"}), 400
        
        # Get challenge from session
        challenge_b64 = session.get("auth_challenge")
        if not challenge_b64:
            return jsonify({"success": False, "error": "No challenge found"}), 400
        
        challenge = base64.b64decode(challenge_b64)
        
        # Find the user and credential
        users = load_users()
        found_user = None
        found_passkey = None
        
        for username, user_data in users.items():
            if 'passkeys' in user_data:
                for passkey in user_data['passkeys']:
                    if passkey["id"] == credential["id"]:
                        found_user = username
                        found_passkey = passkey
                        break
                if found_user:
                    break
        
        if not found_user or not found_passkey:
            return jsonify({"success": False, "error": "Credential not found"})
        
        # Verify authentication
        verification = verify_authentication_response(
            credential={
                "id": credential["id"],
                "rawId": credential["rawId"],
                "response": {
                    "authenticatorData": credential["response"]["authenticatorData"],
                    "clientDataJSON": credential["response"]["clientDataJSON"],
                    "signature": credential["response"]["signature"],
                    "userHandle": credential["response"]["userHandle"] if credential["response"]["userHandle"] else None
                },
                "type": credential["type"]
            },
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64.b64decode(found_passkey["public_key"]),
            credential_current_sign_count=found_passkey["sign_count"]
        )
        
        if verification:
            # Update sign count
            found_passkey["sign_count"] = verification.new_sign_count
            save_users(users)
            
            # Login user
            session["user"] = found_user
            session.pop("auth_challenge", None)
            
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Authentication failed"})
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    # Check if SSL certificates exist
    if os.path.exists("ssl/cert.pem") and os.path.exists("ssl/key.pem"):
        app.run(host="0.0.0.0", port=8080, ssl_context=('ssl/cert.pem', 'ssl/key.pem'), debug=True)
    else:
        print("SSL certificates not found. Please run install.sh first or generate certificates manually.")
        print("For testing without SSL, the app will run on HTTP (Passkeys require HTTPS)")
        app.run(host="0.0.0.0", port=8080, debug=True)

