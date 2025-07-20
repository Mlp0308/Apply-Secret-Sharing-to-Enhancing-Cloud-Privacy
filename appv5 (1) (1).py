import email_notifications
from flask import Flask, Response, request, render_template, redirect, session, make_response, jsonify
from flask_jwt_extended import set_access_cookies, create_access_token, jwt_required, JWTManager, get_jwt_identity
from secret_ket import jwt_secret_key, flask_secret_key
from datetime import timedelta
import time
import json
import os
import io
from bcrypt import *
from hmac import compare_digest
import boto3
from werkzeug.utils import secure_filename
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from secret_sharing import generate_shares
from reconstruct_secret import reconstruct_secret
from utils import display_shares
from email_notifications import notify_share_generated, notify_secret_reconstructed
import traceback

# Initialize the Flask app
app = Flask(__name__)
CORS(app)

# JWT Configuration
app.secret_key = flask_secret_key
app.config['JWT_SECRET_KEY'] = jwt_secret_key
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)

# AWS S3 Configuration
S3_BUCKET_NAME = "2levelsecurityaccess"
AWS_ACCESS_KEY = "AKIAYS2NSM4XDIUQIE7R"
AWS_SECRET_KEY = "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"
AWS_REGION = "us-east-1"

# Create a session for S3
s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

# Role-based Permissions
ADMIN_ROLE = "ADMIN"
MANAGER_ROLE = "MANAGER"
EMPLOYEE_ROLE = "EMPLOYEE"

# User session and login tracking
login_attempt = 0
stat_time, waiting_time = 1, 0
create_acnt = ''

# Mock data for users
users = {
    "admin": {"role": ADMIN_ROLE, "email": "admin@example.com"},
    "manager": {"role": MANAGER_ROLE, "email": "manager@example.com"},
    "employee": {"role": EMPLOYEE_ROLE, "email": "employee@example.com"},
}

# Email configuration
sender_email = 'lokanadam@gmail.com'
sender_password = 'scml xmih dlpc kbtc'

# Improved Encryption/Decryption Functions
def get_encryption_key(secret_key, salt=None):
    """Generate a Fernet key from a secret key string
    
    Args:
        secret_key (str): The secret key to derive the encryption key from
        salt (bytes, optional): Salt for key derivation. If None, generates a new random salt
                              which should be stored for decryption.
    
    Returns:
        tuple: (key, salt) where key is the encryption key and salt is the salt used
    """
    if salt is None:
        # In production, generate a new salt for each encryption
        # This enhances security but requires storing the salt with the encrypted data
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    return key, salt

def encrypt_file(file_data, secret_key):
    """Encrypt file data using the provided secret key
    
    Args:
        file_data (bytes): The file data to encrypt
        secret_key (str): The secret key to use for encryption
        
    Returns:
        bytes: The encrypted data with salt prepended
    """
    key, salt = get_encryption_key(secret_key)
    f = Fernet(key)
    encrypted_data = f.encrypt(file_data)
    
    # Prepend the salt to the encrypted data for later decryption
    return str(salt) + str(encrypted_data)

def decrypt_file(encrypted_data, secret_key):
    """Decrypt file data using the provided secret key
    
    Args:
        encrypted_data (bytes): The encrypted data with salt prepended
        secret_key (str): The secret key to use for decryption
        
    Returns:
        bytes: The decrypted data or None if decryption fails
    """
    try:
        # Extract the salt (first 16 bytes)
        salt = encrypted_data[:16]
        actual_encrypted_data = encrypted_data[16:]
        
        # Get the key using the extracted salt
        key, _ = get_encryption_key(secret_key, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(actual_encrypted_data)
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Ensure user_database directory exists
os.makedirs('user_database', exist_ok=True)

def load_user_credentials():
    try:
        with open('user_database/user_credentials.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Initialize with empty credentials if file doesn't exist or is invalid
        init_data = {"cred": []}
        with open('user_database/user_credentials.json', 'w') as f:
            json.dump(init_data, f, indent=4)
        return init_data

# Index file rendering
@app.route('/', methods=['POST', 'GET'])
def main():
    global login_attempt, create_acnt
    if 'is_logged_in' not in session:
        if request.method == 'POST':
            # Login logic
            name = request.form['user_name']
            password = request.form['paswd']

            try:
                # Getting user data from the database
                user_cred = load_user_credentials()

                # Checking the user name in the database
                user_name_in_database = None
                for data in user_cred['cred']:
                    if compare_digest(name, data['user_id']):
                        user_name_in_database = data
                        break
                
                if not user_name_in_database:
                    create_acnt = "Create an account"
                    return redirect("/register")

                if checkpw(password.encode("utf-8"), user_name_in_database['password'].encode("utf-8")):
                    status = user_name_in_database['status']
                    if status == 'INACTIVE':
                        return render_template("login.html", error="Account is inactive. Please check your email for activation.")
                    
                    session['user_id'] = user_name_in_database['user_id']
                    session['is_logged_in'] = True
                    session['user_role'] = user_name_in_database['role']
                    session['email'] = user_name_in_database['email']
                    
                    # Implementing JWT
                    access_token = create_access_token(identity=session['user_id'])

                    resp = make_response(render_template("index.html", name=session['user_id'], role=session['user_role']))
                    set_access_cookies(resp, access_token)
                    return resp
                else:
                    login_attempt += 1
                    return render_template("login.html", error="Invalid credentials")
            except Exception as e:
                print(f"Login error: {e}")
                return render_template("login.html", error="An error occurred. Please try again.")
        return redirect("/login")
    else:
        return render_template('index.html', name=session['user_id'], role=session.get('user_role'))

# Login page rendering
@app.route("/login")
def login_page():
    global login_attempt, stat_time, waiting_time
    if "is_logged_in" not in session:
        if login_attempt == 4:
            stat_time = time.time()
            waiting_time = 600  # 10 minutes
            login_attempt += 1
        elif login_attempt >= 10:
            stat_time = time.time()
            waiting_time = 3600  # 1 hour
            login_attempt = 0
        
        elapsed_time = time.time() - stat_time
        if waiting_time > 0 and elapsed_time <= waiting_time:
            return render_template("blocked_page.html", set_time=waiting_time)
        else:
            waiting_time = 0  # Reset waiting time once it's expired
            if login_attempt >= 1:
                return render_template("login.html", error="Invalid credentials")
            return render_template("login.html")
    else:
        return redirect("/")

@app.route('/activate', methods=['GET'])
def activate():
    email = request.args.get('id')
    if not email:
        return redirect("/login")
        
    user_cred = load_user_credentials()
    
    for data in user_cred['cred']:
        if compare_digest(email, data['email']):
            data['status'] = 'ACTIVE'
            with open('user_database/user_credentials.json', 'w') as file:
                json.dump(user_cred, file, indent=4)
            return render_template("login.html", message="Account activated successfully! You can now login.")
    
    return redirect("/login")

# Register logic
@app.route("/register", methods=['POST', 'GET'])
def register_page():
    global create_acnt
    if 'is_logged_in' not in session:
        if request.method == 'POST':
            f_name = request.form['first_name']
            l_name = request.form['last_name']
            email = request.form['email']
            role = request.form['role']
            password = request.form['passwd']
            password_re = request.form['passwd_re']
            
            # Validate input
            if len(f_name) >= 10 or len(l_name) >= 10:
                return render_template("register.html", error="First name and last name must be less than 10 characters")
            
            if len(password) < 8 or len(password) > 20:
                return render_template("register.html", error="Password must be between 8 and 20 characters")
                
            if password != password_re:
                return render_template("register.html", error="Passwords do not match")
            
            # Check if email already exists
            user_cred = load_user_credentials()
            for data in user_cred['cred']:
                if data['email'] == email:
                    return render_template("register.html", error="Email already exists")
            
            if role == 'EMPLOYEE':
                status = 'INACTIVE'
                subject = "Employee Register Request"
                body = f"Please click the link to <a href='http://127.0.0.1:5000/activate?id={email}'>activate</a> the employee account\n\nBest regards,\nSecurity System"
                recipient_email = sender_email
                try:
                    email_notifications.send_email(subject, body, recipient_email, sender_email, sender_password)
                except Exception as e:
                    print(f"Error sending email: {e}")
            else:
                status = 'ACTIVE'

            user_data = {
                'user_id': f"{f_name}_{l_name}",
                'first name': f_name,
                'last name': l_name,
                'email': email,
                'role': role,
                'password': hashpw(password.encode('utf-8'), salt=gensalt()).decode('utf-8'),
                're-password': hashpw(password_re.encode('utf-8'), salt=gensalt()).decode('utf-8'),
                'status': status
            }

            try:
                user_cred['cred'].insert(0, user_data)
                with open('user_database/user_credentials.json', 'w') as file:
                    json.dump(user_cred, file, indent=4)
                return render_template("login.html", message="Registration successful! You can now login." if status == 'ACTIVE' else "Registration successful! Please wait for account activation.")
            except Exception as e:
                print(f"Registration error: {e}")
                return render_template("register.html", error="An error occurred during registration. Please try again.")
                
        return render_template("register.html", error=create_acnt)
    return redirect("/")

# Logout logic
@app.route("/logout")
def logout_logic():
    session.clear()
    resp = make_response(redirect("/login"))
    for cookie_name in request.cookies:
        resp.delete_cookie(cookie_name)
    return resp

# Protected page route
@app.route("/protected", methods=['POST', 'GET'])
@jwt_required()
def protected_page():
    if 'is_logged_in' not in session:
        return redirect("/login")
        
    project_det = "The client wants to build a so-called Google map for finding the location of Dora's house"
    company_det = "Investment: 70,000 USD; Profit: 10,000 USD"
    employee_det = "Name: 'xxx'; Age: 45"
    
    data = request.form.get("role")
    if not data:
        return render_template('index.html', name=session['user_id'], role=session.get('user_role'))
    
    try:
        with open("user_database/user_credentials.json") as file:
            data_file = json.loads(file.read())
            if session['user_role'] == 'MANAGER' or session['user_role'] == 'ADMIN':
                employee_det = data_file 
    except Exception as e:
        print(f"Error loading credentials: {e}")
    
    msg = "ACCESS DENIED"
    if (data == 'employee_details' or data == "project details") and session['user_role'] == 'MANAGER':
        if data == "employee_details":
            msg = employee_det
        elif data == 'project details':
            msg = project_det
    elif (data == 'firm details' or data == 'employee_details' or data == "project details") and session['user_role'] == 'ADMIN':
        if data == "employee_details":
            msg = employee_det['cred']
        elif data == 'project details':
            msg = project_det
        elif data == 'firm details':
            msg = company_det
    if data == 'project details' and session['user_role'] == 'EMPLOYEE':
        msg = project_det

    if msg != "ACCESS DENIED":
        return render_template('details.html', infotype=data, name=session['user_id'], protected_msg=msg, role=session.get('user_role'))

    return render_template('index.html', infotype=data, name=session['user_id'], protected_msg=msg, role=session.get('user_role'))

@app.route('/upload_page', methods=['GET'])
@jwt_required()
def upload_page():
    # Check if the user is logged in and is an ADMIN
    if 'user_role' not in session or session['user_role'] != 'ADMIN':
        return "Access Denied", 403  # If not ADMIN, deny access
    
    return render_template('upload_page.html')  # GET request renders the upload form

# S3 File Upload route
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'is_logged_in' not in session or session['user_role'] != 'ADMIN':
        return jsonify({"message": "Permission denied. Admin role required."}), 403

    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if 'secret' not in request.form:
        return jsonify({"message": "No secret key provided"}), 400
        
    secret = request.form['secret']
    if not secret:
        return jsonify({"message": "Secret key cannot be empty"}), 400
        
    try:
        threshold = int(request.form.get('threshold', 2))
    except ValueError:
        return jsonify({"message": "Threshold must be a number"}), 400

    filename = secure_filename(file.filename)
    
    try:
        # Read the file data
        file_data = file.read()
        
        # Encrypt the file data using improved encryption
        encrypted_data = encrypt_file(file_data, secret)
        
        # Upload the encrypted file to S3
        s3.upload_fileobj(
            io.BytesIO(encrypted_data),
            S3_BUCKET_NAME,
            f"encrypted_{filename}"
        )
        
        # Save the mapping of filename to original filename for reference
        try:
            with open('file_mappings.json', 'r') as f:
                file_mappings = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            file_mappings = {}
            
        file_mappings[f"encrypted_{filename}"] = filename
        
        with open('file_mappings.json', 'w') as f:
            json.dump(file_mappings, f)
        
        # Save the secret, filename, and threshold for future reference
        try:
            with open('secrets.json', 'r') as f:
                secrets_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            secrets_data = {}
        
        secrets_data[f"encrypted_{filename}"] = {
            "original_filename": filename,
            "secret": secret,
            "threshold": threshold
        }
        
        with open('secrets.json', 'w') as f:
            json.dump(secrets_data, f)
            
        # Generate and distribute shares
        user_credentials = load_user_credentials()
        
        # Get the emails of employees
        recipient_emails = [
            user['email'] for user in user_credentials['cred'] if user['role'] == 'EMPLOYEE' and user['status'] == 'ACTIVE'
        ]
        
        if not recipient_emails:
            return jsonify({"message": "No active employees found to share with"}), 400
            
        # Generate shares for the secret key
        shares = generate_shares(secret, len(recipient_emails), threshold)
        
        # Store the shares (for demo/backup purposes)
        with open('shares.json', 'w') as f:
            json.dump({"filename": f"encrypted_{filename}", "shares": shares}, f)
        
        # Send emails with shares to employees
        for i, email in enumerate(recipient_emails):
            if i < len(shares):
                share_info = f"Your share for file '{filename}' is: Share #{shares[i][0]} -> {shares[i][1]}"
                try:
                    notify_share_generated(email, sender_email, sender_password, share_info)
                    print(f"Email sent to {email} with their share.")
                except Exception as e:
                    print(f"Error sending email to {email}: {e}")
        
        return jsonify({
            "message": f"File {filename} encrypted and uploaded successfully! Secret shares have been distributed to {len(recipient_emails)} employees.",
            "filename": f"encrypted_{filename}"
        }), 200
        
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"message": f"Error processing file: {str(e)}"}), 500

# S3 File List route
@app.route('/list-files', methods=['GET'])
@jwt_required()
def list_files():
    if 'is_logged_in' not in session:
        return redirect("/login")
        
    try:
        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME)
        
        if 'Contents' not in response:
            return render_template('file_list.html', files=[], role=session['user_role'])
            
        files = response['Contents']
        file_names = [file['Key'] for file in files]
        
        # Load file mappings to show original filenames
        try:
            with open('file_mappings.json', 'r') as f:
                file_mappings = json.load(f)
                
            file_info = [
                {"encrypted_name": name, "original_name": file_mappings.get(name, name)}
                for name in file_names
            ]
        except (FileNotFoundError, json.JSONDecodeError):
            file_info = [{"encrypted_name": name, "original_name": name} for name in file_names]
            
        return render_template('file_list.html', files=file_info, role=session['user_role'])
    except Exception as e:
        print(f"Error listing files: {e}")
        return jsonify({"message": f"Error listing files: {str(e)}"}), 500

# S3 File Download route
@app.route('/download/<filename>', methods=['POST'])
@jwt_required()
def download_file(filename):
    if 'is_logged_in' not in session:
        return redirect("/login")
        
    try:
        # Get the shares from the form
        shares = []
        for i in range(1, 4):  # Assuming 3 shares maximum
            share_id = request.form.get(f's{i}1')
            share_value = request.form.get(f's{i}2')
            
            if share_id and share_value:
                try:
                    shares.append((int(share_id), int(share_value)))
                except ValueError:
                    continue
        
        if not shares:
            return jsonify({"message": "No valid shares provided"}), 400
            
        # Reconstruct the secret
        try:
            reconstructed_secret = reconstruct_secret(shares)
            print(f"Reconstructed secret: {reconstructed_secret}")
        except Exception as e:
            print(f"Error reconstructing secret: {e}")
            return jsonify({"message": "Failed to reconstruct secret from shares"}), 400
        
        # Verify the secret is valid for this file
        secret_valid = False
        try:
            with open('secrets.json', 'r') as f:
                secrets_data = json.load(f)
                
            if filename in secrets_data and secrets_data[filename]["secret"] == reconstructed_secret:
                secret_valid = True
                original_filename = secrets_data[filename]["original_filename"]
            else:
                return jsonify({"message": "Invalid shares for this file"}), 403
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"Error verifying secret: {e}")
            
            # Fallback to checking secrets.txt for backward compatibility
            try:
                with open('secrets.txt', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if f"Secret: {reconstructed_secret}" in line and f"Filename: {filename}" in line:
                            secret_valid = True
                            original_filename = filename.replace("encrypted_", "")
                            break
            except FileNotFoundError:
                pass
        
        if not secret_valid:
            # Send an alert email to admin
            try:
                admin_email = next((user['email'] for user in load_user_credentials()['cred'] 
                                   if user['role'] == 'ADMIN'), sender_email)
                
                subject = "Security Alert: Failed Decryption Attempt"
                body = f"User {session.get('user_id')} ({session.get('email')}) attempted to download file {filename} with invalid shares."
                
                email_notifications.send_email(subject, body, admin_email, sender_email, sender_password)
            except Exception as e:
                print(f"Error sending security alert: {e}")
                
            return jsonify({"message": "Invalid shares for this file. This attempt has been logged."}), 403
            
        try:
            # Get the encrypted file from S3
            file_obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
            encrypted_data = file_obj['Body'].read()
            
            # Decrypt the file using improved decryption
            decrypted_data = decrypt_file(encrypted_data, reconstructed_secret)
            
            if decrypted_data is None:
                return jsonify({"message": "Failed to decrypt file with provided shares"}), 400
                
            # Log successful download
            notify_secret_reconstructed(
                session.get('email', 'user@example.com'), 
                sender_email, 
                sender_password, 
                f"File {original_filename} was successfully downloaded by {session.get('user_id')}."
            )
                
            # Return the decrypted file
            return Response(
                decrypted_data,
                mimetype='application/octet-stream',
                headers={"Content-Disposition": f"attachment;filename={original_filename}"}
            )
        except Exception as e:
            print(f"Error downloading/decrypting file: {e}")
            return jsonify({"message": f"Error processing file: {str(e)}"}), 500
            
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"message": f"Error downloading file: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)