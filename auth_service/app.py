from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import json, hashlib, base64, os
import pyotp
import qrcode
from io import BytesIO
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference, AuthenticatorAttachment
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(16)
USER_FILE = "users.json"

# WebAuthn configuration
RP_ID = "merkur"  # Domain name 
RP_NAME = "HAW IT-Security Lab"
ORIGIN = "https://auth.merkur"  # origin

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
    return redirect(url_for("login"))

@app.route("/logout")  
def logout():
    session.clear()
    return redirect(url_for("login"))

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
        app.run(host="0.0.0.0", port=5000, ssl_context=('ssl/cert.pem', 'ssl/key.pem'), debug=True)
    else:
        print("SSL certificates not found. Please run install.sh first or generate certificates manually.")
        print("For testing without SSL, the app will run on HTTP (Passkeys require HTTPS)")
        app.run(host="0.0.0.0", port=5000, debug=True)

