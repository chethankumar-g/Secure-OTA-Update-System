from flask import Flask, request, render_template, url_for, send_file
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from encipher import encrypt_update, decrypt_update, derive_shared_key
from logger import program_logger
import os
import datetime
import time
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
allIP = '0.0.0.0'

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  
    default_limits=["10 per minute"],  
    strategy="fixed-window-elastic-expiry")
blocked_ips = {}
BLOCK_SEC = 60

UPLOAD_FOLDER = 'uploads/'
UPDATE_FOLDER = 'updates/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(UPDATE_FOLDER, exist_ok=True)

server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()

OTA_UPDATE = {"version": "1.0.1", "file_path": os.path.join(UPDATE_FOLDER, "ota_update_1.0.1.txt")}

UPDATE_HISTORY = []

def log_update(version, status):
    log_entry = {"version": version, "timestamp": datetime.datetime.now().isoformat(), "status": status}
    UPDATE_HISTORY.append(log_entry)
    program_logger.info(f"Update {version}: {status}")

@app.before_request
def block_ip_check():
    client_ip = get_remote_address()

    # Check if the IP is currently blocked
    if client_ip in blocked_ips:
        remaining_time = blocked_ips[client_ip] - time.time()
        if remaining_time > 0:
            return (render_template("429.html", message=f"You are temporarily blocked. Retry in {int(remaining_time)} seconds."),429)
        else:
            del blocked_ips[client_ip]

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/upload_update", methods=["GET", "POST"])
def upload_update():
    if request.method == "POST":
        if 'file' not in request.files:
            return render_template("upload_update.html", message="No file part")

        file = request.files['file']
        if file.filename == '':
            return render_template("upload_update.html", message="No selected file")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        OTA_UPDATE["file_path"] = file_path
        log_update(OTA_UPDATE["version"], "uploaded")
        return render_template("upload_update.html", message="File uploaded successfully")

    return render_template("upload_update.html")

@app.route("/fetch_update", methods=["GET","POST"])
def fetch_update():
    if request.method == "POST":
        if OTA_UPDATE["file_path"] is None or not os.path.exists(OTA_UPDATE["file_path"]):
            log_update(OTA_UPDATE["version"], "file not found")
            return render_template("fetch_update.html", fetch_response=None, error="No OTA file found.")

        # Generate client private/public keys
        client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        client_public_key = client_private_key.public_key()

        # Derive the shared key
        shared_key = derive_shared_key(client_private_key, server_public_key)

        # Encrypt the OTA file
        with open(OTA_UPDATE["file_path"], "rb") as f:
            file_bytes = f.read()
        encrypted_content = encrypt_update(file_bytes, shared_key)

        # Save encrypted file temporarily
        encrypted_file_path = os.path.join(UPDATE_FOLDER, f"encrypted_ota_update_{OTA_UPDATE['version']}.txt")
        with open(encrypted_file_path, "wb") as f:
            f.write(base64.b64decode(encrypted_content))

        log_update(OTA_UPDATE["version"], "distributed (encrypted)")

        # Redirect to decrypt.html with the file and public key coordinates
        client_public_key_coords = {
            "x": client_public_key.public_numbers().x,
            "y": client_public_key.public_numbers().y,
        }

        return render_template(
            "decrypt_update.html",
            file_path=encrypted_file_path,
            public_key_coords=client_public_key_coords
        )
    else:
        return render_template("fetch_update.html")


@app.route("/decrypt_update", methods=["GET","POST"])
def decrypt_update():
    if request.method=="POST":
    # Check for the uploaded encrypted file
        if 'file' not in request.files:
            return render_template("decrypt_update.html", message="No file uploaded.")

        file = request.files['file']
        if file.filename == '':
            return render_template("decrypt_update.html", message="No file selected.")

        # Save the uploaded encrypted file temporarily
        uploaded_file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(uploaded_file_path)

        # Extract client public key from headers
        try:
            client_public_key_coords = {
                "x": int(request.headers.get("Client-Public-Key-X")),
                "y": int(request.headers.get("Client-Public-Key-Y"))
            }
            client_public_key = ec.EllipticCurvePublicNumbers(
                client_public_key_coords["x"], client_public_key_coords["y"], ec.SECP256R1()
            ).public_key(default_backend())

            # Decrypt the uploaded file
            with open(uploaded_file_path, "rb") as f:
                encrypted_content = f.read()
            shared_key = derive_shared_key(server_private_key, client_public_key)
            decrypted_bytes = decrypt_update(base64.b64encode(encrypted_content).decode(), shared_key)

            # Save decrypted file
            decrypted_file_path = os.path.join(UPLOAD_FOLDER, "decrypted_" + file.filename)
            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_bytes)

            log_update(OTA_UPDATE["version"], "decrypted successfully")
            message = f"The file has been successfully decrypted and saved as {os.path.basename(decrypted_file_path)}."
            status = "valid"

        except Exception as e:
            log_update(OTA_UPDATE["version"], f"decryption failed: {str(e)}")
            message = f"Decryption failed: {str(e)}"
            status = "invalid"

        # Clean up temporary uploaded file
        os.remove(uploaded_file_path)

        return render_template("decrypt_update.html",decrypt_response={"status": status, "message": message},public_key_coords={'x':0,'y':0})
    else:
        return render_template("decrypt_update.html",public_key_coords={'x':0,'y':0})

@app.route("/verify_update", methods=["GET","POST"])
def verify_update():
    if request.method=="POST":
        # Check for the uploaded update file
        if 'file' not in request.files:
            return render_template("verify_update.html", message="No file uploaded.")

        file = request.files['file']
        if file.filename == '':
            return render_template("verify_update.html", message="No file selected.")

        # Save the uploaded file temporarily
        uploaded_file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(uploaded_file_path)

        try:
            # Check if the uploaded file matches the server's latest update file
            if OTA_UPDATE["file_path"] is None or not os.path.exists(OTA_UPDATE["file_path"]):
                os.remove(uploaded_file_path)  # Clean up temporary file
                return render_template(
                    "verify_update.html",
                    verify_response={"status": "invalid", "message": "No reference update file found on the server."}
                )

            with open(OTA_UPDATE["file_path"], "rb") as server_file:
                server_file_content = server_file.read()

            with open(uploaded_file_path, "rb") as uploaded_file:
                uploaded_file_content = uploaded_file.read()

            # Compare file contents
            if uploaded_file_content != server_file_content:
                os.remove(uploaded_file_path)  # Clean up temporary file
                return render_template(
                    "verify_update.html",
                    verify_response={"status": "invalid", "message": "The uploaded file does not match the server's reference update file."}
                )

            # Check if the uploaded file is the latest version
            uploaded_file_version = request.form.get("version")
            if uploaded_file_version != OTA_UPDATE["version"]:
                os.remove(uploaded_file_path)  # Clean up temporary file
                return render_template(
                    "verify_update.html",
                    verify_response={"status": "invalid", "message": "The uploaded file is not the latest version. Expected version: {}."
                                .format(OTA_UPDATE["version"])}
                )

            # If everything is valid
            log_update(uploaded_file_version, "verified successfully")
            message = "The uploaded file is valid and matches the latest version."
            status = "valid"

        except Exception as e:
            log_update("unknown", f"verification failed: {str(e)}")
            message = f"Verification failed: {str(e)}"
            status = "invalid"

        # Clean up temporary uploaded file
        os.remove(uploaded_file_path)

        return render_template(
            "verify_update.html",
            verify_response={"status": status, "message": message}
        )
    else:
        return render_template("verify_update.html")

@app.route("/rollback", methods=["POST", "GET"])
def rollback():
    if request.method == "GET":
        # Render rollback page with available versions
        available_versions = [entry["version"] for entry in UPDATE_HISTORY if entry["status"] == "distributed"]
        return render_template("rollback.html", versions=available_versions)

    if request.method == "POST":
        rollback_version = request.form.get("rollback_version")
        matching_updates = [entry for entry in UPDATE_HISTORY if entry["version"] == rollback_version]

        if not matching_updates:
            return render_template(
                "rollback.html",
                message=f"Version {rollback_version} not found in update history.",
                versions=[entry["version"] for entry in UPDATE_HISTORY if entry["status"] == "distributed"],
            )

        rollback_file_path = os.path.join(UPDATE_FOLDER, f"ota_update_{rollback_version}.txt")
        if not os.path.exists(rollback_file_path):
            return render_template(
                "rollback.html",
                message=f"The file for version {rollback_version} is missing on the server.",
                versions=[entry["version"] for entry in UPDATE_HISTORY if entry["status"] == "distributed"],
            )

        OTA_UPDATE["file_path"] = rollback_file_path
        OTA_UPDATE["version"] = rollback_version
        log_update(rollback_version, "rollback completed")

        return render_template(
            "rollback.html",
            message=f"Rollback to version {rollback_version} completed successfully.",
            versions=[entry["version"] for entry in UPDATE_HISTORY if entry["status"] == "distributed"],
        )


@app.route("/history", methods=["GET","POST"])
def view_history():
    if request.method=="POST":
        return render_template("history.html", history_response={"update_history": UPDATE_HISTORY})
    else:
        return render_template("history.html",history_response={})

"""@app.errorhandler(429)
def ratelimit_error(e):
    client_ip = get_remote_address()
    
    # Block the IP by recording its timeout
    if client_ip not in blocked_ips:
        blocked_ips[client_ip] = time.time() + BLOCK_SEC

    return (render_template("429.html", message=f"You are temporarily blocked. Retry in {int(BLOCK_SEC-blocked_ips[client_ip])} seconds."),429)"""


if __name__ == "__main__":
    app.run(debug=True, host=allIP, port=10000)
