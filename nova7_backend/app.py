# In nova7_backend/app.py, starting from the imports and Flask app init
# (Ensure all necessary imports are at the very top, as you had them)

import os
from dotenv import load_dotenv
import csv
from io import StringIO
import uuid
from flask import Flask, request, jsonify, make_response
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, JSON, or_
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token, JWTManager, jwt_required, get_jwt_identity, decode_token
)
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flask_wtf.csrf import CSRFProtect, generate_csrf # KEEP this one, it's correct
from functools import wraps
from werkzeug.utils import secure_filename
from google.cloud import storage
import google.generativeai as genai
import json
import tempfile
from flask_migrate import Migrate
import logging
from flask_bcrypt import Bcrypt

# --- Flask App Initialization ---
app = Flask(__name__)

# --- App Configuration (ALL config lines should be here, *before* extensions that depend on them) ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secure-csrf-secret-key-2025-nova7')

# IMPORTANT: SQLALCHEMY_DATABASE_URI MUST BE SET *before* db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', # Use DATABASE_URL for Vercel, as previously discussed
    'postgresql+pg8000://neondb_owner:npg_KWJLx8l6UiEj@ep-winter-bush-a8i3nb89-pooler.eastus2.azure.neon.tech/neondb?sslmode=require' # Fallback for local dev if DATABASE_URL is not set
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended to suppress warning

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-jwt-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# --- Mail Config ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@nova7.com')


# --- Initialize ALL Extensions ONCE (after app and its config are ready) ---
bcrypt = Bcrypt(app) # MOVED HERE - now initialized only once and after configs
jwt = JWTManager(app)
csrf = CSRFProtect(app)
db = SQLAlchemy(app) # This will now correctly find SQLALCHEMY_DATABASE_URI
migrate = Migrate(app, db)
mail = Mail(app)


# --- Gemini API Setup ---
# Consider moving GEMINI_API_KEY to app.config and using os.getenv
GEMINI_API_KEY = "AIzaSyA-gi3C5e4ZnN5wLvX3h9XUEgAIyOtu6aw"
genai.configure(api_key=GEMINI_API_KEY)
print(f"Gemini API configured with key: {GEMINI_API_KEY[:8]}...")

# ... (the rest of your app.py file, including Google Cloud Auth, .env loading, and CORS setup, should follow here, unchanged from your last provided snippet) ...

# For clarity, the CORS setup block is shown again below,
# but it should already be correct in your file after the previous steps.
# --- CORS Configuration ---
CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'https://nova7-fawn.vercel.app,http://127.0.0.1:5500,http://127.0.0.1:5501').split(',')

def get_cors_origin_dynamic():
    origin = request.headers.get('Origin')
    if origin and origin in CORS_ORIGINS:
        return origin
    return []

CORS(app, resources={r"/api/*": {
    "origins": get_cors_origin_dynamic,
    "supports_credentials": True,
    "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token", "x-csrf-token"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "expose_headers": ["X-CSRF-Token"]
}})
print(f"Allowed CORS origins: {CORS_ORIGINS}")

# --- Upload Folder ---
UPLOAD_FOLDER = '/tmp/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER) # This will now work in /tmp
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Google Cloud Storage ---
try:
    storage_client = storage.Client()
    GCS_BUCKET_NAME = os.getenv('GCS_BUCKET_NAME')
    if GCS_BUCKET_NAME:
        gcs_bucket = storage_client.get_bucket(GCS_BUCKET_NAME)
        print(f"Connected to GCS bucket: {GCS_BUCKET_NAME}")
    else:
        print("Warning: GCS_BUCKET_NAME not set.")
except Exception as e:
    print(f"Error initializing GCS: {e}")
    gcs_bucket = None

# --- Optional Email Override for Debug ---
def disable_email_send(self, message):
    print(f"Email would have sent to {message.recipients} | Subject: {message.subject}")
    return None
# Mail.send = disable_email_send

# --- Routes ---
import os
from datetime import datetime, timedelta
import uuid
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token, decode_token
from flask_cors import CORS
# from google.cloud import storage # Uncomment if you're directly using Google Cloud Storage client
# --- Configuration ---
# Use environment variables for sensitive data and configuration in production.
# Provide a default for local development, but ensure these are set in Vercel.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# --- Upload Folder (for temporary files on Vercel) ---
# Files here are temporary and will be deleted after the function invocation.
# For persistent storage, use Google Cloud Storage or another external service.
UPLOAD_FOLDER = '/tmp/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Initialize Extensions ---


# Configure CORS for your frontend domains
# Ensure these origins are exactly what your frontend uses (e.g., "https://your-frontend-domain.vercel.app")
cors = CORS(app, origins=[
    "https://nova7-frontend.onrender.com",
    "http://127.0.0.1:5500", # For local development
    "http://127.0.0.1:5501", # For local development
    "https://nova7.vercel.app" # Your Vercel frontend domain
], supports_credentials=True)

# --- Google Cloud Storage Client Initialization (Conditional) ---
# This block attempts to initialize the GCS client.
# It relies on GOOGLE_APPLICATION_CREDENTIALS_JSON being set in Vercel environment variables.
# Uncomment and adapt if you are using GCS directly in your app.
# try:
#     gcs_client = storage.Client()
#     print("Google Cloud Storage client initialized successfully.")
# except Exception as e:
#     print(f"Error initializing GCS: {e}. Please ensure GOOGLE_APPLICATION_CREDENTIALS_JSON is set in Vercel.")

# --- Routes ---
# This is the updated root route to return JSON, typical for an API backend.
# Your frontend should be making API calls to specific endpoints (e.g., /api/login, /api/users)
# and not expecting the backend to serve HTML directly for the main page.
@app.route('/')
def api_root_status():
    return jsonify({"status": "Backend API is online", "message": "Welcome to the Nova7 API! Access specific endpoints for data."}), 200

# Your login.html should be part of your frontend project, deployed as static assets.
# Remove the old serve_frontend function if it was trying to send login.html.
# @app.route('/')
# def serve_frontend():
#     return app.send_static_file('login.html')

# --- JWT Handlers ---
@jwt.invalid_token_loader
def invalid_token_callback(callback_error):
    print(f"JWT Invalid Token: {callback_error}")
    return jsonify({"status": "error", "message": "Invalid token.", "details": str(callback_error)}), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("JWT Expired Token")
    return jsonify({"status": "error", "message": "Token expired."}), 401

@app.route('/api/debug-env-vars', methods=['GET'])
def debug_env_vars():
    secret_key_val = os.getenv('SECRET_KEY')
    cors_origins_val = os.getenv('CORS_ORIGINS')
    
    # Return a JSON response with the values
    return jsonify({
        "status": "success",
        "SECRET_KEY_READ": secret_key_val if secret_key_val else "NOT_SET_OR_EMPTY",
        "CORS_ORIGINS_READ": cors_origins_val if cors_origins_val else "NOT_SET_OR_EMPTY"
    })

# --- Models ---
# Your existing models remain here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    id_number = db.Column(db.String(50), unique=True, nullable=True)
    biometric_data = db.Column(db.String(255), nullable=True)
    country = db.Column(db.String(100), nullable=False)
    payment_network = db.Column(db.String(100), nullable=False)
    mobile_money = db.Column(db.String(100), nullable=False)
    province = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    phone_number = db.Column(db.String(20), nullable=False)
    data_consent = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expiration = db.Column(db.DateTime, nullable=True)
    profile_picture_url = db.Column(db.String(255), nullable=True)
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    income_sources = db.Column(db.String, nullable=True)
    expenses = db.Column(db.String, nullable=True)
    debt = db.Column(db.String, nullable=True)
    financial_goals = db.Column(db.String, nullable=True)

    # Relationships
    transactions = db.relationship(
        'Transaction',
        backref='user',
        lazy=True,
        foreign_keys='Transaction.user_id'
    )

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'public_id': self.public_id,
            'full_name': self.full_name,
            'email': self.email,
            'date_of_birth': str(self.date_of_birth) if self.date_of_birth else None,
            'id_number': self.id_number,
            'biometric_data': self.biometric_data,
            'country': self.country,
            'payment_network': self.payment_network,
            'mobile_money': self.mobile_money,
            'province': self.province,
            'city': self.city,
            'address': self.address,
            'phone_number': self.phone_number,
            'data_consent': self.data_consent,
            'is_admin': self.is_admin,
            'email_verified': self.email_verified,
            'profile_picture_url': self.profile_picture_url,
            'balance': float(self.balance),
            'income_sources': self.income_sources,
            'expenses': self.expenses,
            'debt': self.debt,
            'financial_goals': self.financial_goals
        }

class UserSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    language = db.Column(db.String(10), default='en')
    email_notifications_enabled = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(20), default='light')

    def to_dict(self):
        return {
            'language': self.language,
            'email_notifications_enabled': self.email_notifications_enabled,
            'theme': self.theme
        }

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(60), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # deposit, withdrawal, etc.
    status = db.Column(db.String(50), default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255), nullable=True)
    office_withdrawal_details = db.Column(JSON, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'transaction_id': self.transaction_id,
            'user_id': self.user_id,
            'receiver_id': self.receiver_id,
            'amount': float(self.amount),
            'type': self.type,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'office_withdrawal_details': self.office_withdrawal_details
        }

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    quantity = db.Column(db.Integer, default=0) # NEW: Quantity can reduce or grow
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_available = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'seller_id': self.seller_id,
            'name': self.name,
            'description': self.description,
            'price': float(self.price),
            'quantity': self.quantity,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat(),
            'is_available': self.is_available
        }

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    borrower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Null if system-provided or from a pool
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    interest_rate = db.Column(db.Numeric(5, 2), nullable=False)
    term_months = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending') # e.g., 'pending', 'approved', 'rejected', 'active', 'paid'
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    # Add more fields like repayment schedule, current balance, etc.

    def to_dict(self):
        return {
            'id': self.id,
            'borrower_id': self.borrower_id,
            'lender_id': self.lender_id,
            'amount': float(self.amount),
            'interest_rate': float(self.interest_rate),
            'term_months': self.term_months,
            'status': self.status,
            'request_date': self.request_date.isoformat(),
            'approval_date': self.approval_date.isoformat() if self.approval_date else None,
            'due_date': self.due_date.isoformat() if self.due_date else None
        }

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=True)
    # Features included, e.g., for TII
    features = db.Column(JSON, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'price': float(self.price),
            'description': self.description,
            'features': self.features
        }

class UserSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscription.id'), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    # Add fields for Stripe subscription ID if integrated

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'subscription_id': self.subscription_id,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'is_active': self.is_active
        }

class CommunityPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True) # NEW: For post photos
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'content': self.content,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat()
        }

class MoneyRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='pending') # 'pending', 'approved', 'rejected', 'completed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'amount': float(self.amount),
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'responded_at': self.responded_at.isoformat() if self.responded_at else None
        }


# --- Utility Functions ---
def token_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if not current_user or not current_user.is_admin:
            return jsonify({"status": "error", "message": "Admin access required"}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Removed _build_cors_preflight_response function as Flask-CORS handles this automatically
# def _build_cors_preflight_response():
#     response = make_response()
#     response.headers.add("Access-Control-Allow-Origin", ", ".join(CORS_ORIGINS))
#     response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRFToken")
#     response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
#     response.headers.add("Access-Control-Allow-Credentials", "true")
#     return response

# --- Run App ---
# This block is for local development. Vercel's build process handles running the app.
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # This creates tables based on your models
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
    
@app.route('/api/debug-env', methods=['GET'])
def debug_env():
    return jsonify({
        "status": "success",
        "secret_key": os.getenv('SECRET_KEY', 'Not found'),
        "cors_origins": os.getenv('CORS_ORIGINS', 'Not found')
    })

@app.route('/drop_alembic_version', methods=['POST'])
def drop_alembic_version():
    # Optional: add auth here to restrict access to admins only
    try:
        db.engine.execute("DROP TABLE IF EXISTS alembic_version;")
        return jsonify({"status": "success", "message": "Dropped alembic_version table successfully."})
    except Exception as e:
        print(f"Error dropping alembic_version table: {e}")
        return jsonify({"status": "error", "message": f"Error dropping alembic_version table: {str(e)}"}), 500

@app.route('/api/csrf-token', methods=['GET', 'OPTIONS'])
@csrf.exempt
def get_csrf_token():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "https://nova7-fawn.vercel.app")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
        response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

    try:
        token = generate_csrf()
        response = jsonify({'csrf_token': token, 'status': 'success'})
        response.headers.set('Access-Control-Allow-Origin', 'https://nova7-fawn.vercel.app')
        response.headers.set('Access-Control-Allow-Credentials', 'true')
        response.headers.set('X-CSRF-Token', token)
        return response, 200
    except Exception as e:
        print(f"Error generating CSRF token: {e}")
        return jsonify({"status": "error", "message": f"Failed to generate CSRF token: {str(e)}"}), 500

@app.route('/api/register', methods=['POST', 'OPTIONS'])
@csrf.exempt # CSRF protection might need to be handled differently for file uploads or be exempted
def register_user():
    # --- NEW: Explicitly handle OPTIONS requests for CORS preflight ---
    if request.method == 'OPTIONS':
        # Flask-CORS will automatically add the necessary Access-Control-Allow-Headers,
        # Access-Control-Allow-Methods, and Access-Control-Allow-Origin headers
        # based on the CORS configuration for the app.
        return make_response("", 200)

    try:
        # --- START OF CHANGES FOR MULTIPART/FORM-DATA ---
        # Instead of request.get_json(), access form fields from request.form
        # and files from request.files
        full_name = request.form.get('fullName')
        date_of_birth_str = request.form.get('dateOfBirth') # Get as string
        id_number = request.form.get('idNumber')
        payment_network = request.form.get('paymentNetwork')
        mobile_money = request.form.get('mobileMoney')
        country = request.form.get('country')
        province = request.form.get('province')
        city = request.form.get('city')
        address = request.form.get('address')
        phone_number = request.form.get('phoneNumber')
        email = request.form.get('email')
        password = request.form.get('password') # Assuming password is sent as part of form
        data_consent = request.form.get('dataConsent') == 'true' # Convert string "true" to boolean True

        biometric_file = request.files.get('biometricData') # Get the file object

        # Convert date_of_birth string to Date object
        date_of_birth = None
        if date_of_birth_str:
            try:
                date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid date of birth format. Use YYYY-MM-DD."}), 400

        # Basic validation (add more as needed)
        if not all([full_name, email, password, country, payment_network, mobile_money, phone_number]):
            return jsonify({"status": "error", "message": "Missing required fields (Full Name, Email, Password, Country, Payment Network, Mobile Money, Phone Number)."}), 400

        if not id_number and not biometric_file:
            return jsonify({"status": "error", "message": "Please provide either an ID number or biometric data."}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"status": "error", "message": "Email already registered."}), 409

        # Handle biometric data upload
        biometric_data_url = None
        if biometric_file and gcs_bucket:
            try:
                # Generate a unique filename for GCS
                unique_filename = f"biometric_data/{uuid.uuid4()}_{secure_filename(biometric_file.filename)}"
                blob = gcs_bucket.blob(unique_filename)
                blob.upload_from_file(biometric_file)
                biometric_data_url = blob.public_url # Or signed URL if private
            except Exception as e:
                print(f"GCS upload error for biometric data: {e}")
                return jsonify({"status": "error", "message": "Failed to upload biometric data."}), 500
        elif biometric_file and not gcs_bucket:
            # Fallback to local storage if GCS not configured (not recommended for production)
            filename = secure_filename(biometric_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            biometric_file.save(file_path)
            biometric_data_url = file_path # Store local path

        # Create new user
        new_user = User(
            full_name=full_name,
            date_of_birth=date_of_birth,
            id_number=id_number,
            biometric_data=biometric_data_url, # Store the URL/path
            country=country,
            payment_network=payment_network,
            mobile_money=mobile_money,
            province=province,
            city=city,
            address=address,
            phone_number=phone_number,
            email=email,
            data_consent=data_consent
        )
        new_user.set_password(password) # Hash the password

        db.session.add(new_user)
        db.session.commit()

        # --- END OF CHANGES FOR MULTIPART/FORM-DATA ---

        return jsonify({"status": "success", "message": "Registration successful! Please verify your email."}), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {str(e)}")
        return jsonify({"status": "error", "message": f"An error occurred during registration: {str(e)}"}), 500

from flask_bcrypt import Bcrypt

from werkzeug.security import check_password_hash  # import at the top

@app.route('/api/login', methods=['POST'])
@csrf.exempt
def login_user():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            app.logger.warning("Invalid login request: missing email or password")
            return jsonify({"status": "error", "message": "Email and password are required."}), 400

        email = data['email'].strip().lower()
        password = data['password']

        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()

        if user:
            print(f"Stored hash for user {email}: {user.password_hash}")

        if not user or not check_password_hash(user.password_hash, password):
            app.logger.warning(f"Login failed for {email}: invalid credentials")
            return jsonify({"status": "error", "message": "Invalid email or password."}), 401

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(hours=1))
        app.logger.info(f"Login successful for {email}")

        return jsonify({
            "status": "success",
            "message": "Login successful",
            "access_token": access_token,
            "user": user.to_dict()
        }), 200

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500
@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    # This is a placeholder. You'll expand this for dashboard data.
    return jsonify({
        "status": "success",
        "message": f"Welcome to your dashboard, {current_user.full_name}!",
        "user_balance": float(current_user.balance), # Add more dashboard specific data here, e.g., recent transactions, insights
        "recent_transactions": [t.to_dict() for t in current_user.transactions[-5:]] # Last 5 transactions
    }), 200

@app.route('/api/balance', methods=['GET'])
@token_required
def get_balance(current_user):
    # Already existed, ensuring it uses the new 'balance' field
    return jsonify({"status": "success", "balance": float(current_user.balance)}), 200


@app.route('/api/settings', methods=['GET', 'PUT'])
@csrf.exempt
@token_required
def settings_endpoint(current_user):
    settings = UserSetting.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSetting(user_id=current_user.id)
        db.session.add(settings)
        db.session.commit()

    if request.method == 'GET':
        return jsonify({"status": "success", "settings": settings.to_dict()}), 200
    elif request.method == 'PUT':
        data = request.json
        try:
            if 'language' in data:
                settings.language = data['language']
            if 'email_notifications_enabled' in data:
                settings.email_notifications_enabled = data['email_notifications_enabled']
            if 'theme' in data:
                settings.theme = data['theme']
            db.session.commit()
            return jsonify({"status": "success", "message": "Settings updated successfully.", "settings": settings.to_dict()}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating settings: {e}")
            return jsonify({"status": "error", "message": "Failed to update settings."}), 500

@app.route('/api/forgot-password', methods=['POST'])
@csrf.exempt
def forgot_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "User with that email does not exist."}), 404

    # Generate a unique token
    token = str(uuid.uuid4())
    user.password_reset_token = token
    # Token valid for 1 hour
    user.password_reset_expiration = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()

    # --- NEW: Email sending logic (if enabled) ---
    reset_link = f"http://localhost:5501/reset-password.html?token={token}" # Adjust for your frontend URL
    msg = Message("Password Reset Request for Nova7",
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    msg.body = f"Hello {user.full_name},\n\nYou have requested a password reset for your Nova7 account. Please click on the following link to reset your password:\n\n{reset_link}\n\nThis link will expire in 1 hour.\n\nIf you did not request a password reset, please ignore this email."
    
    try:
        if app.config.get('MAIL_SERVER') and app.config.get('MAIL_USERNAME'): # Only attempt if mail is configured
            mail.send(msg)
            print(f"Password reset email sent to {user.email}")
        else:
            print(f"Mail server not configured. Password reset link: {reset_link}") # For local testing without email
            return jsonify({"status": "success", "message": "Password reset email link printed to console (mail not configured).", "reset_link": reset_link}), 200

        return jsonify({"status": "success", "message": "Password reset email sent."}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error sending password reset email: {e}")
        return jsonify({"status": "error", "message": "Failed to send password reset email."}), 500

@app.route('/api/reset-password', methods=['POST'])
@csrf.exempt
def reset_password():
    token = request.json.get('token')
    new_password = request.json.get('newPassword')

    user = User.query.filter_by(password_reset_token=token).first()

    if not user or user.password_reset_expiration < datetime.utcnow():
        return jsonify({"status": "error", "message": "Invalid or expired reset token."}), 400

    user.set_password(new_password)
    user.password_reset_token = None # Clear token after use
    user.password_reset_expiration = None
    db.session.commit()

    return jsonify({"status": "success", "message": "Your password has been reset successfully."}), 200

# --- NEW: User Profile Management (including profile picture upload) ---
@app.route('/api/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    return jsonify({"status": "success", "profile": current_user.to_dict()}), 200

@app.route('/api/profile', methods=['PUT'])
@csrf.exempt
@token_required
def update_user_profile(current_user):
    # This endpoint can handle general profile updates (not password or picture)
    data = request.get_json() # Assuming JSON for general profile updates

    try:
        if 'full_name' in data:
            current_user.full_name = data['full_name']
        if 'date_of_birth' in data:
            try:
                current_user.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid date of birth format. Use YYYY-MM-DD."}), 400
        if 'id_number' in data:
            current_user.id_number = data['id_number']
        if 'country' in data:
            current_user.country = data['country']
        if 'payment_network' in data:
            current_user.payment_network = data['payment_network']
        if 'mobile_money' in data:
            current_user.mobile_money = data['mobile_money']
        if 'province' in data:
            current_user.province = data['province']
        if 'city' in data:
            current_user.city = data['city']
        if 'address' in data:
            current_user.address = data['address']
        if 'phone_number' in data:
            current_user.phone_number = data['phone_number']

        db.session.commit()
        return jsonify({"status": "success", "message": "Profile updated successfully.", "profile": current_user.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating profile: {e}")
        return jsonify({"status": "error", "message": "Failed to update profile."}), 500

@app.route('/api/profile/picture', methods=['POST'])
@csrf.exempt
@token_required
def upload_profile_picture(current_user):
    if 'profilePicture' not in request.files:
        return jsonify({"status": "error", "message": "No profilePicture part in the request."}), 400

    file = request.files['profilePicture']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file."}), 400

    if file and gcs_bucket:
        try:
            unique_filename = f"profile_pictures/{uuid.uuid4()}_{secure_filename(file.filename)}"
            blob = gcs_bucket.blob(unique_filename)
            blob.upload_from_file(file)
            current_user.profile_picture_url = blob.public_url
            db.session.commit()
            return jsonify({"status": "success", "message": "Profile picture uploaded to GCS.", "url": blob.public_url}), 200
        except Exception as e:
            db.session.rollback()
            print(f"GCS upload error for profile picture: {e}")
            return jsonify({"status": "error", "message": "Failed to upload profile picture."}), 500
    elif file and not gcs_bucket:
        # Fallback to local storage if GCS not configured (not recommended for production)
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        current_user.profile_picture_url = file_path
        db.session.commit()
        return jsonify({"status": "success", "message": "Profile picture uploaded locally", "url": file_path}), 200
    else:
        return jsonify({"status": "error", "message": "GCS not configured and no local fallback."}), 500

# --- NEW: Wallet & Transaction Routes ---
@app.route('/api/wallet/deposit', methods=['POST'])
@csrf.exempt
@token_required
def deposit_money(current_user):
    amount = request.json.get('amount')
    description = request.json.get('description', 'Deposit')

    if not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid deposit amount."}), 400

    try:
        current_user.balance += amount
        transaction = Transaction(
            user_id=current_user.id,
            amount=amount,
            type='deposit',
            status='completed',
            description=description
        )
        db.session.add(transaction)
        db.session.commit()
        return jsonify({"status": "success", "message": "Deposit successful.", "new_balance": float(current_user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during deposit: {e}")
        return jsonify({"status": "error", "message": "Failed to process deposit."}), 500

@app.route('/api/wallet/withdraw', methods=['POST'])
@csrf.exempt
@token_required
def request_withdrawal(current_user):
    amount = request.json.get('amount')
    mobile_money_account = request.json.get('mobileMoneyAccount') # For mobile money withdrawal
    office_withdrawal = request.json.get('officeWithdrawal', False) # True if office withdrawal
    office_details = request.json.get('officeDetails') # Details for office withdrawal

    if not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid withdrawal amount."}), 400

    if current_user.balance < amount:
        return jsonify({"status": "error", "message": "Insufficient balance for withdrawal."}), 400

    # Basic validation for withdrawal method
    if office_withdrawal and not office_details:
        return jsonify({"status": "error", "message": "Office withdrawal selected, but office details are missing."}), 400
    if not office_withdrawal and not mobile_money_account:
        return jsonify({"status": "error", "message": "Neither office withdrawal nor mobile money account provided."}), 400

    try:
        # Deduct balance immediately upon request, mark as pending
        current_user.balance -= amount
        
        withdrawal_type = 'withdrawal_office' if office_withdrawal else 'withdrawal_mobile_money'
        description = f"Withdrawal request via {withdrawal_type.replace('withdrawal_', '').replace('_', ' ')}"
        if office_details:
            description += f" (Office: {office_details.get('name')})"

        transaction = Transaction(
            user_id=current_user.id,
            amount=-amount, # Store as negative to represent debit
            type=withdrawal_type,
            status='pending', # Withdrawals often require approval
            description=description,
            office_withdrawal_details=office_details if office_withdrawal else None
        )
        db.session.add(transaction)
        db.session.commit()

        # In a real app, you'd trigger an internal process for approval/disbursement
        return jsonify({"status": "success", "message": "Withdrawal request submitted successfully. It is pending approval.", "new_balance": float(current_user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during withdrawal request: {e}")
        return jsonify({"status": "error", "message": "Failed to process withdrawal request."}), 500

@app.route('/api/wallet/transfer', methods=['POST'])
@csrf.exempt
@token_required
def transfer_money(current_user):
    receiver_email = request.json.get('receiverEmail')
    amount = request.json.get('amount')
    description = request.json.get('description', 'Money transfer')

    if not receiver_email or not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid receiver email or amount."}), 400

    if current_user.balance < amount:
        return jsonify({"status": "error", "message": "Insufficient balance for transfer."}), 400

    receiver = User.query.filter_by(email=receiver_email).first()
    if not receiver:
        return jsonify({"status": "error", "message": "Receiver not found."}), 404

    if receiver.id == current_user.id:
        return jsonify({"status": "error", "message": "Cannot transfer money to yourself."}), 400

    try:
        # Deduct from sender
        current_user.balance -= amount
        sender_transaction = Transaction(
            user_id=current_user.id,
            receiver_id=receiver.id,
            amount=-amount, # Negative for outgoing
            type='transfer_sent',
            status='completed',
            description=description
        )
        db.session.add(sender_transaction)

        # Add to receiver
        receiver.balance += amount
        receiver_transaction = Transaction(
            user_id=receiver.id,
            receiver_id=current_user.id,
            amount=amount, # Positive for incoming
            type='transfer_received',
            status='completed',
            description=description
        )
        db.session.add(receiver_transaction)

        db.session.commit()
        return jsonify({"status": "success", "message": "Money transferred successfully.", "new_balance": float(current_user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during transfer: {e}")
        return jsonify({"status": "error", "message": "Failed to process transfer."}), 500

@app.route('/api/wallet/love-payment', methods=['POST'])
@csrf.exempt
@token_required
def love_payment(current_user):
    receiver_email = request.json.get('receiverEmail')
    amount = request.json.get('amount')
    description = request.json.get('description', 'Love payment')

    if not receiver_email or not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid receiver email or amount."}), 400

    if current_user.balance < amount:
        return jsonify({"status": "error", "message": "Insufficient balance for love payment."}), 400

    receiver = User.query.filter_by(email=receiver_email).first()
    if not receiver:
        return jsonify({"status": "error", "message": "Receiver not found."}), 404

    if receiver.id == current_user.id:
        return jsonify({"status": "error", "message": "Cannot send love payment to yourself."}), 400

    try:
        # Deduct from sender
        current_user.balance -= amount
        sender_transaction = Transaction(
            user_id=current_user.id,
            receiver_id=receiver.id,
            amount=-amount,
            type='love_payment_sent',
            status='completed',
            description=description
        )
        db.session.add(sender_transaction)

        # Add to receiver
        receiver.balance += amount
        receiver_transaction = Transaction(
            user_id=receiver.id,
            receiver_id=current_user.id,
            amount=amount,
            type='love_payment_received',
            status='completed',
            description=description
        )
        db.session.add(receiver_transaction)

        db.session.commit()
        return jsonify({"status": "success", "message": "Love payment sent successfully.", "new_balance": float(current_user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during love payment: {e}")
        return jsonify({"status": "error", "message": "Failed to process love payment."}), 500

@app.route('/api/admin/withdrawal-requests', methods=['GET'])
@admin_required
def get_withdrawal_requests(current_user):
    # Admin can view all pending withdrawal requests
    pending_withdrawals = Transaction.query.filter(
        (Transaction.type == 'withdrawal_office') | (Transaction.type == 'withdrawal_mobile_money'),
        Transaction.status == 'pending'
    ).all()
    
    return jsonify({
        "status": "success",
        "pending_withdrawals": [w.to_dict() for w in pending_withdrawals]
    }), 200

@app.route('/api/admin/withdrawal-requests/<int:transaction_id>', methods=['POST'])
@admin_required
def process_withdrawal_request(current_user, transaction_id):
    action = request.json.get('action') # 'approve' or 'reject'
    transaction = Transaction.query.get(transaction_id)

    if not transaction:
        return jsonify({"status": "error", "message": "Transaction not found."}), 404

    if transaction.type not in ['withdrawal_office', 'withdrawal_mobile_money'] or transaction.status != 'pending':
        return jsonify({"status": "error", "message": "Invalid transaction for this action or not pending."}), 400

    try:
        if action == 'approve':
            transaction.status = 'completed'
            # The amount was already deducted as negative in the request_withdrawal
            # So no need to deduct from user balance again.
            db.session.commit()
            # TODO: In a real system, trigger the actual money disbursement here
            # and potentially notify the user that their withdrawal is approved and processed
            return jsonify({"status": "success", "message": f"Withdrawal {transaction_id} approved and processed."}), 200
        elif action == 'reject':
            transaction.status = 'rejected'
            # If rejected, return the money to the user's balance
            user = User.query.get(transaction.user_id)
            if user:
                user.balance -= transaction.amount # transaction.amount is negative, so this adds it back
            db.session.commit()
            # TODO: Notify user that withdrawal is rejected and funds returned
            return jsonify({"status": "success", "message": f"Withdrawal {transaction_id} rejected and funds returned."}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid action. Must be 'approve' or 'reject'."}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error processing withdrawal approval/rejection: {e}")
        return jsonify({"status": "error", "message": "Failed to process withdrawal action."}), 500

# --- NEW: Marketplace Routes ---
@app.route('/api/marketplace/products', methods=['POST'])
@csrf.exempt
@token_required
def create_product(current_user):
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    quantity = request.form.get('quantity')
    image_file = request.files.get('productImage')

    if not all([name, price, quantity]) or not isinstance(float(price), (int, float)) or not isinstance(int(quantity), int) or float(price) <= 0 or int(quantity) < 0:
        return jsonify({"status": "error", "message": "Missing or invalid product details."}), 400

    image_url = None
    if image_file:
        if gcs_bucket:
            try:
                unique_filename = f"product_images/{uuid.uuid4()}_{secure_filename(image_file.filename)}"
                blob = gcs_bucket.blob(unique_filename)
                blob.upload_from_file(image_file)
                image_url = blob.public_url
            except Exception as e:
                print(f"GCS upload error for product image: {e}")
                return jsonify({"status": "error", "message": "Failed to upload image."}), 500
        elif not gcs_bucket:
            # Fallback to local storage if GCS not configured (not recommended for production)
            filename = secure_filename(image_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(file_path)
            image_url = file_path # Store local path

    try:
        new_product = Product(
            seller_id=current_user.id,
            name=name,
            description=description,
            price=float(price),
            quantity=int(quantity),
            image_url=image_url
        )
        db.session.add(new_product)
        db.session.commit()
        return jsonify({"status": "success", "message": "Product created successfully.", "product": new_product.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating product: {e}")
        return jsonify({"status": "error", "message": "Failed to create product."}), 500

@app.route('/api/marketplace/products', methods=['GET'])
def get_products():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    search_query = request.args.get('search', '')
    category = request.args.get('category', '') # You'd need a 'category' field in your Product model
    sort_by = request.args.get('sort', 'created_at') # 'created_at', 'price', 'name'
    order = request.args.get('order', 'desc') # 'asc' or 'desc'

    products_query = Product.query.filter_by(is_available=True)

    if search_query:
        products_query = products_query.filter(
            or_(
                Product.name.ilike(f'%{search_query}%'),
                Product.description.ilike(f'%{search_query}%')
            )
        )
    
    # if category:
    #     products_query = products_query.filter_by(category=category) # Requires a category field

    if sort_by == 'price':
        products_query = products_query.order_by(Product.price.asc() if order == 'asc' else Product.price.desc())
    elif sort_by == 'name':
        products_query = products_query.order_by(Product.name.asc() if order == 'asc' else Product.name.desc())
    else: # Default to created_at
        products_query = products_query.order_by(Product.created_at.desc() if order == 'desc' else Product.created_at.asc())

    paginated_products = products_query.paginate(page=page, per_page=limit, error_out=False)

    products_data = [product.to_dict() for product in paginated_products.items]

    return jsonify({
        "status": "success",
        "products": products_data,
        "current_page": paginated_products.page,
        "total_pages": paginated_products.pages,
        "total_results": paginated_products.total
    }), 200

@app.route('/api/marketplace/products/<int:product_id>', methods=['GET'])
def get_product_details(product_id):
    product = Product.query.get(product_id)
    if not product or not product.is_available:
        return jsonify({"status": "error", "message": "Product not found or not available."}), 404
    return jsonify({"status": "success", "product": product.to_dict()}), 200

@app.route('/api/marketplace/buy/<int:product_id>', methods=['POST'])
@csrf.exempt
@token_required
def buy_product(current_user, product_id):
    quantity_to_buy = request.json.get('quantity', 1) # Default to 1 if not specified

    product = Product.query.get(product_id)

    if not product or not product.is_available or product.quantity < quantity_to_buy:
        return jsonify({"status": "error", "message": "Product not available or insufficient stock."}), 400

    TRANSACTION_FEE_RATE = 0.01 # 1% fee for example
    product_price_per_item = product.price
    total_cost_items = product_price_per_item * quantity_to_buy
    transaction_fee = total_cost_items * TRANSACTION_FEE_RATE
    total_charge_to_buyer = total_cost_items + transaction_fee

    if current_user.balance < total_charge_to_buyer:
        return jsonify({"status": "error", "message": "Insufficient balance to buy this product (including transaction fee). Your balance is " + str(current_user.balance) + " and required is " + str(total_charge_to_buyer)}), 400

    try:
        # Deduct from buyer
        current_user.balance -= total_charge_to_buyer
        buyer_transaction = Transaction(
            user_id=current_user.id,
            receiver_id=product.seller_id,
            amount=-total_charge_to_buyer, # Negative for outgoing
            type='product_buy',
            status='completed',
            description=f"Bought {quantity_to_buy} x {product.name} (incl. fee)"
        )
        db.session.add(buyer_transaction)

        # Add to seller (seller receives product_price_per_item * quantity_to_buy, fee is charged to buyer)
        seller = User.query.get(product.seller_id)
        if seller:
            seller.balance += total_cost_items # Seller gets the item price, not affected by buyer's fee
            seller_transaction = Transaction(
                user_id=seller.id,
                receiver_id=current_user.id,
                amount=total_cost_items, # Positive for incoming
                type='product_sell',
                status='completed',
                description=f"Sold {quantity_to_buy} x {product.name}"
            )
            db.session.add(seller_transaction)

        # Update product quantity
        product.quantity -= quantity_to_buy
        if product.quantity == 0:
            product.is_available = False # Mark as unavailable if stock runs out

        db.session.commit()
        return jsonify({"status": "success", "message": f"Successfully purchased {quantity_to_buy} x {product.name}.", "new_balance": float(current_user.balance)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during product purchase: {e}")
        return jsonify({"status": "error", "message": "Failed to process purchase."}), 500

@app.route('/api/loans/request', methods=['POST'])
@csrf.exempt
@token_required
def request_loan(current_user):
    amount = request.json.get('amount')
    interest_rate = request.json.get('interestRate')
    term_months = request.json.get('termMonths')

    if not all([amount, interest_rate, term_months]) or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid loan amount, interest rate, or term."}), 400

    try:
        new_loan = Loan(
            borrower_id=current_user.id,
            amount=float(amount),
            interest_rate=float(interest_rate),
            term_months=int(term_months),
            status='pending' # Loans usually start as pending approval
        )
        db.session.add(new_loan)
        db.session.commit()
        return jsonify({"status": "success", "message": "Loan request submitted successfully. Awaiting approval.", "loan": new_loan.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error requesting loan: {e}")
        return jsonify({"status": "error", "message": "Failed to submit loan request."}), 500

@app.route('/api/loans', methods=['GET'])
@token_required
def get_user_loans(current_user):
    loans = Loan.query.filter_by(borrower_id=current_user.id).order_by(Loan.request_date.desc()).all()
    return jsonify({"status": "success", "loans": [loan.to_dict() for loan in loans]}), 200

@app.route('/api/admin/loan-requests', methods=['GET'])
@admin_required
def get_loan_requests(current_user):
    pending_loans = Loan.query.filter_by(status='pending').all()
    return jsonify({"status": "success", "pending_loans": [loan.to_dict() for loan in pending_loans]}), 200

@app.route('/api/admin/loan-requests/<int:loan_id>', methods=['POST'])
@admin_required
def process_loan_request(current_user, loan_id):
    action = request.json.get('action') # 'approve' or 'reject'
    loan = Loan.query.get(loan_id)

    if not loan:
        return jsonify({"status": "error", "message": "Loan request not found."}), 404

    if loan.status != 'pending':
        return jsonify({"status": "error", "message": "Loan is not pending approval."}), 400

    try:
        if action == 'approve':
            loan.status = 'active'
            loan.approval_date = datetime.utcnow()
            loan.due_date = loan.approval_date + timedelta(days=loan.term_months * 30) # Approximate due date

            # Add loan amount to borrower's balance
            borrower = User.query.get(loan.borrower_id)
            if borrower:
                borrower.balance += loan.amount
                # Record as a transaction
                transaction = Transaction(
                    user_id=borrower.id,
                    amount=loan.amount,
                    type='loan_received',
                    status='completed',
                    description=f"Loan approved: {loan.amount} for {loan.term_months} months"
                )
                db.session.add(transaction)
            db.session.commit()
            # TODO: Notify borrower of loan approval
            return jsonify({"status": "success", "message": f"Loan {loan_id} approved."}), 200
        elif action == 'reject':
            loan.status = 'rejected'
            db.session.commit()
            # TODO: Notify borrower of loan rejection
            return jsonify({"status": "success", "message": f"Loan {loan_id} rejected."}), 400
        else:
            return jsonify({"status": "error", "message": "Invalid action. Must be 'approve' or 'reject'."}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error processing loan approval/rejection: {e}")
        return jsonify({"status": "error", "message": "Failed to process loan action."}), 500

# --- NEW: Insurance (TII) Routes ---
@app.route('/api/subscriptions', methods=['GET'])
def get_subscriptions():
    subscriptions = Subscription.query.all()
    return jsonify({"status": "success", "subscriptions": [s.to_dict() for s in subscriptions]}), 200

@app.route('/api/subscribe', methods=['POST'])
@csrf.exempt
@token_required
def subscribe_to_tii(current_user):
    subscription_id = request.json.get('subscriptionId')
    # In a real app, you'd integrate with Stripe or another payment gateway here
    # For now, we'll simulate immediate activation

    subscription = Subscription.query.get(subscription_id)
    if not subscription:
        return jsonify({"status": "error", "message": "Subscription plan not found."}), 404

    # Check if user already has an active subscription of this type
    active_user_sub = UserSubscription.query.filter_by(user_id=current_user.id, subscription_id=subscription_id, is_active=True).first()
    if active_user_sub:
        return jsonify({"status": "error", "message": "You already have an active subscription to this plan."}), 409

    try:
        # Deduct subscription price from user's balance
        if current_user.balance < subscription.price:
            return jsonify({"status": "error", "message": "Insufficient balance to subscribe."}), 400
        
        current_user.balance -= subscription.price
        
        new_user_sub = UserSubscription(
            user_id=current_user.id,
            subscription_id=subscription_id,
            start_date=datetime.utcnow(),
            # For simplicity, let's assume a 1-month subscription if no specific end date is provided
            end_date=datetime.utcnow() + timedelta(days=30), 
            is_active=True
        )
        db.session.add(new_user_sub)

        # Record as a transaction
        transaction = Transaction(
            user_id=current_user.id,
            amount=-subscription.price,
            type='subscription_payment',
            status='completed',
            description=f"Payment for {subscription.name} subscription"
        )
        db.session.add(transaction)
        
        db.session.commit()
        return jsonify({"status": "success", "message": f"Successfully subscribed to {subscription.name}!", "user_subscription": new_user_sub.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error subscribing to TII: {e}")
        return jsonify({"status": "error", "message": "Failed to subscribe."}), 500

@app.route('/api/user-subscriptions', methods=['GET'])
@token_required
def get_user_subscriptions(current_user):
    user_subscriptions = UserSubscription.query.filter_by(user_id=current_user.id).all()
    # You might want to join with Subscription model to get subscription details
    subscriptions_data = []
    for us in user_subscriptions:
        sub_dict = us.to_dict()
        subscription_plan = Subscription.query.get(us.subscription_id)
        if subscription_plan:
            sub_dict['plan_details'] = subscription_plan.to_dict()
        subscriptions_data.append(sub_dict)
    return jsonify({"status": "success", "user_subscriptions": subscriptions_data}), 200

# --- NEW: Community Forum Routes ---
@app.route('/api/community/posts', methods=['POST'])
@csrf.exempt
@token_required
def create_community_post(current_user):
    content = request.form.get('content')
    image_file = request.files.get('image') # Assuming 'image' is the field name for file upload

    if not content:
        return jsonify({"status": "error", "message": "Post content cannot be empty."}), 400

    image_url = None
    if image_file:
        if gcs_bucket:
            try:
                unique_filename = f"community_images/{uuid.uuid4()}_{secure_filename(image_file.filename)}"
                blob = gcs_bucket.blob(unique_filename)
                blob.upload_from_file(image_file)
                image_url = blob.public_url
            except Exception as e:
                print(f"GCS upload error for community image: {e}")
                return jsonify({"status": "error", "message": "Failed to upload image."}), 500
        elif not gcs_bucket:
            # Fallback to local storage if GCS not configured (not recommended for production)
            filename = secure_filename(image_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(file_path)
            image_url = file_path

    try:
        new_post = CommunityPost(
            user_id=current_user.id,
            content=content,
            image_url=image_url
        )
        db.session.add(new_post)
        db.session.commit()
        return jsonify({"status": "success", "message": "Post created successfully.", "post": new_post.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating community post: {e}")
        return jsonify({"status": "error", "message": "Failed to create post."}), 500

@app.route('/api/community/posts', methods=['GET'])
@token_required
def get_community_posts(current_user): # Can be accessed by any logged-in user
    posts = CommunityPost.query.order_by(CommunityPost.created_at.desc()).all()
    # You might want to join with User to get user names/profile pictures
    posts_data = []
    for post in posts:
        post_dict = post.to_dict()
        post_user = User.query.get(post.user_id)
        if post_user:
            post_dict['author_name'] = post_user.full_name
            post_dict['author_profile_picture_url'] = post_user.profile_picture_url
        posts_data.append(post_dict)
    return jsonify({"status": "success", "posts": posts_data}), 200

# --- NEW: Stripe Configuration Endpoint ---
@app.route('/api/stripe-config', methods=['GET'])
def get_stripe_config():
    publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
    if not publishable_key:
        return jsonify({"status": "error", "message": "Stripe publishable key not configured on backend."}), 500
    return jsonify({"status": "success", "publishableKey": publishable_key}), 200

# --- NEW: Money Request Endpoint ---
@app.route('/api/wallet/request', methods=['POST'])
@csrf.exempt
@token_required
def request_money(current_user):
    receiver_email = request.json.get('receiverEmail') # This is the person who *owes* the money and will *send* it
    amount = request.json.get('amount')
    description = request.json.get('description', 'Money request')

    if not receiver_email or not amount or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "error", "message": "Invalid receiver email or amount."}), 400

    sender = User.query.filter_by(email=receiver_email).first() # Sender of the money (the one being requested from)
    if not sender:
        return jsonify({"status": "error", "message": "User to request money from not found."}), 404
    
    if sender.id == current_user.id:
        return jsonify({"status": "error", "message": "Cannot request money from yourself."}), 400

    try:
        new_request = MoneyRequest(
            sender_id=sender.id, # The person from whom money is requested
            receiver_id=current_user.id, # The person requesting the money
            amount=amount,
            description=description,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()

        # TODO: Implement notification to the 'sender' (the person from whom money is requested)
        # e.g., send an email or an in-app notification.

        return jsonify({"status": "success", "message": "Money request sent successfully. Awaiting sender's action.", "request": new_request.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during money request: {e}")
        return jsonify({"status": "error", "message": "Failed to send money request."}), 500

@app.route('/api/wallet/requests/received', methods=['GET'])
@token_required
def get_received_money_requests(current_user):
    # Get requests where current_user is the receiver (i.e., someone requested money from them)
    requests = MoneyRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
    requests_data = []
    for req in requests:
        req_dict = req.to_dict()
        requester = User.query.get(req.receiver_id)
        if requester:
            req_dict['requester_name'] = requester.full_name
            req_dict['requester_email'] = requester.email
        requests_data.append(req_dict)
    return jsonify({"status": "success", "requests": requests_data}), 200

@app.route('/api/wallet/requests/sent', methods=['GET'])
@token_required
def get_sent_money_requests(current_user):
    # Get requests where current_user is the sender (i.e., they requested money from someone)
    requests = MoneyRequest.query.filter_by(receiver_id=current_user.id).all()
    requests_data = []
    for req in requests:
        req_dict = req.to_dict()
        sender = User.query.get(req.sender_id)
        if sender:
            req_dict['sender_name'] = sender.full_name
            req_dict['sender_email'] = sender.email
        requests_data.append(req_dict)
    return jsonify({"status": "success", "requests": requests_data}), 200

@app.route('/api/wallet/requests/<int:request_id>/respond', methods=['POST'])
@csrf.exempt
@token_required
def respond_to_money_request(current_user, request_id):
    action = request.json.get('action') # 'approve' or 'reject'
    money_request = MoneyRequest.query.get(request_id)

    if not money_request:
        return jsonify({"status": "error", "message": "Money request not found."}), 404

    # Ensure the current user is the one from whom the money was requested (the sender_id)
    if money_request.sender_id != current_user.id:
        return jsonify({"status": "error", "message": "You are not authorized to respond to this request."}), 403

    if money_request.status != 'pending':
        return jsonify({"status": "error", "message": "This request has already been responded to."}), 400

    try:
        if action == 'approve':
            if current_user.balance < money_request.amount:
                return jsonify({"status": "error", "message": "Insufficient balance to approve this request."}), 400
            
            # Deduct from current user (sender)
            current_user.balance -= money_request.amount
            sender_transaction = Transaction(
                user_id=current_user.id,
                receiver_id=money_request.receiver_id,
                amount=-money_request.amount,
                type='money_request_sent',
                status='completed',
                description=f"Payment for money request (ID: {money_request.id})"
            )
            db.session.add(sender_transaction)

            # Add to receiver
            requester = User.query.get(money_request.receiver_id)
            if requester:
                requester.balance += money_request.amount
                receiver_transaction = Transaction(
                    user_id=requester.id,
                    receiver_id=current_user.id,
                    amount=money_request.amount,
                    type='money_request_received',
                    status='completed',
                    description=f"Received payment for money request (ID: {money_request.id})"
                )
                db.session.add(receiver_transaction)
            
            money_request.status = 'completed'
            money_request.responded_at = datetime.utcnow()
            db.session.commit()
            return jsonify({"status": "success", "message": "Money request approved and transferred.", "new_balance": float(current_user.balance)}), 200
        
        elif action == 'reject':
            money_request.status = 'rejected'
            money_request.responded_at = datetime.utcnow()
            db.session.commit()
            return jsonify({"status": "success", "message": "Money request rejected."}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid action. Must be 'approve' or 'reject'."}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error responding to money request: {e}")
        return jsonify({"status": "error", "message": "Failed to respond to money request."}), 500

@app.route('/api/wallet/withdrawal-requests', methods=['GET'])
@token_required
def get_user_withdrawal_requests(current_user):
    try:
        pending_withdrawals = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.type.in_(['withdrawal_office', 'withdrawal_mobile_money']),
            Transaction.status == 'pending'
        ).all()
        return jsonify({
            "status": "success",
            "pending_withdrawals": [w.to_dict() for w in pending_withdrawals]
        }), 200
    except Exception as e:
        print(f"Error fetching withdrawal requests: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch withdrawal requests."}), 500

@app.route('/api/wallet/transactions/report', methods=['GET'])
@token_required
def get_transaction_report(current_user):
    try:
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
        return jsonify({
            "status": "success",
            "transactions": [t.to_dict() for t in transactions]
        }), 200
    except Exception as e:
        print(f"Error fetching transaction report: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch transaction report."}), 500


    
@app.route('/api/community/love_donation', methods=['POST'])
@jwt_required()
def love_donation():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        donation_amount = 1.00

        if user.balance < donation_amount:
            return jsonify({'error': 'Insufficient balance for donation'}), 400

        data = request.get_json()
        post_id = data.get('post_id')

        if not post_id:
            return jsonify({'error': 'Post ID is required for donation'}), 400

        user.balance -= donation_amount

        new_transaction = Transaction(
            user_id=user.id,
            amount=-donation_amount,
            type='love_donation',
            description=f'Donation for community post {post_id}',
            recipient_id=None
        )

        db.session.add(new_transaction)
        db.session.commit()

        return jsonify({
            'message': f'Successfully donated ${donation_amount:.2f} for community post {post_id}',
            'new_balance': float(user.balance)
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error processing love donation: {str(e)}")
        return jsonify({'error': 'Failed to process donation'}), 500

# --- NEW: General Transactions/Reports Endpoint (combining previous requests) ---
@app.route('/api/transactions', methods=['GET'])
@token_required
def get_user_transactions(current_user):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    transaction_type = request.args.get('type', '') # e.g., 'deposit', 'withdrawal', 'transfer', 'product_buy', 'product_sell', 'loan', 'subscription'
    start_date_str = request.args.get('startDate')
    end_date_str = request.args.get('endDate')

    query = Transaction.query.filter_by(user_id=current_user.id)

    if transaction_type:
        # Allows for filtering by 'deposit', 'withdrawal', 'transfer', etc.
        # Also handles specific types like 'transfer_sent', 'withdrawal_office' using LIKE
        query = query.filter(
            or_(
                Transaction.type == transaction_type,
                Transaction.type.ilike(f"{transaction_type}\\_%") # Matches 'withdrawal_office' if type is 'withdrawal'
            )
        )
    
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(Transaction.timestamp >= start_date)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid startDate format. Use YYYY-MM-DD."}), 400

    if end_date_str:
        try:
            # Add one day to include transactions on the end_date
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) 
            query = query.filter(Transaction.timestamp < end_date)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid endDate format. Use YYYY-MM-DD."}), 400

    # Order by timestamp for chronological reports
    query = query.order_by(Transaction.timestamp.desc())

    paginated_transactions = query.paginate(page=page, per_page=limit, error_out=False)

    transactions_data = []
    for tx in paginated_transactions.items:
        tx_dict = tx.to_dict()
        # Optionally, fetch sender/receiver names if different from current_user
        if tx.user_id != current_user.id and tx.user_id is not None:
            other_user = User.query.get(tx.user_id)
            if other_user:
                tx_dict['other_party_name'] = other_user.full_name
                tx_dict['other_party_email'] = other_user.email
        elif tx.receiver_id != current_user.id and tx.receiver_id is not None:
            other_user = User.query.get(tx.receiver_id)
            if other_user:
                tx_dict['other_party_name'] = other_user.full_name
                tx_dict['other_party_email'] = other_user.email
        transactions_data.append(tx_dict)

    return jsonify({
        "status": "success",
        "transactions": transactions_data,
        "current_page": paginated_transactions.page,
        "total_pages": paginated_transactions.pages,
        "total_results": paginated_transactions.total
    }), 200

# --- Community Post Likes/Comments (Basic Placeholder) ---
# You'd need new models for PostLike and PostComment
@app.route('/api/community/posts/<int:post_id>/like', methods=['POST'])
@csrf.exempt
@token_required
def like_post(current_user, post_id):
    # This is a placeholder. Implement actual like logic and database updates.
    return jsonify({"status": "success", "message": f"Post {post_id} liked by {current_user.full_name} (placeholder)."}), 200

@app.route('/api/community/posts/<int:post_id>/comment', methods=['POST'])
@csrf.exempt
@token_required
def comment_on_post(current_user, post_id):
    # This is a placeholder. Implement actual comment logic and database updates.
    comment_content = request.json.get('content')
    if not comment_content:
        return jsonify({"status": "error", "message": "Comment content cannot be empty."}), 400
    return jsonify({"status": "success", "message": f"Comment added to post {post_id} by {current_user.full_name}: '{comment_content}' (placeholder)."}), 201

# --- New endpoint for fetching business transactions, could be integrated into /api/transactions with specific type ---
@app.route('/api/business-transactions', methods=['GET'])
@token_required
def get_business_transactions(current_user):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    # The 'type' here refers to 'sale' (product_sell) or 'purchase' (product_buy) from the business perspective
    transaction_type_filter = request.args.get('type', '') 

    query = Transaction.query.filter(
        or_(
            Transaction.user_id == current_user.id,
            Transaction.receiver_id == current_user.id # Include transactions where current_user is the receiver
        )
    )

    # Filter by specific business transaction types
    if transaction_type_filter == 'sale':
        query = query.filter(
            Transaction.type == 'product_sell',
            Transaction.user_id == current_user.id # User is the seller
        )
    elif transaction_type_filter == 'purchase':
        query = query.filter(
            Transaction.type == 'product_buy',
            Transaction.user_id == current_user.id # User is the buyer
        )
    else:
        # If no specific type, show all relevant marketplace transactions for the user
        query = query.filter(
            (Transaction.type == 'product_buy') | 
            (Transaction.type == 'product_sell')
        )


    query = query.order_by(Transaction.timestamp.desc())
    paginated_transactions = query.paginate(page=page, per_page=limit, error_out=False)

    transactions_data = []
    for tx in paginated_transactions.items:
        tx_dict = tx.to_dict()
        # Add details about the other party for clarity in business transactions
        other_party_user = None
        if tx.type == 'product_buy': # Current user is buyer, other party is seller
            other_party_user = User.query.get(tx.receiver_id)
        elif tx.type == 'product_sell': # Current user is seller, other party is buyer
            other_party_user = User.query.get(tx.user_id) if tx.user_id != current_user.id else User.query.get(tx.receiver_id) # Should be the buyer's ID in this context if tx.user_id is seller
        
        if other_party_user:
            tx_dict['other_party_name'] = other_party_user.full_name
            tx_dict['other_party_email'] = other_party_user.email

        # Add transaction fee if applicable and not already in amount
        # For simplicity, if amount is already total, we can infer fee, or store fee explicitly in Transaction model
        # For now, let's assume the amount in DB is the net amount, and frontend can calculate fee if needed
        transactions_data.append(tx_dict)

    return jsonify({
        "status": "success",
        "transactions": transactions_data,
        "current_page": paginated_transactions.page,
        "total_pages": paginated_transactions.pages,
        "total_results": paginated_transactions.total
    }), 200

# This ensures that when app.py is run directly, it will perform database migrations.
# You would typically run `flask db upgrade` from your terminal after changes.

# --- NEW: Update Product Quantity and Delete Product Endpoints ---
@app.route('/api/marketplace/products/<int:product_id>', methods=['PUT'])
@csrf.exempt
@token_required
def update_product_quantity(current_user, product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"status": "error", "message": "Product not found."}), 404
    if product.seller_id != current_user.id:
        return jsonify({"status": "error", "message": "You are not authorized to update this product."}), 403

    data = request.get_json()
    new_quantity = data.get('quantity')
    if new_quantity is None or not isinstance(new_quantity, int) or new_quantity < 0:
        return jsonify({"status": "error", "message": "Invalid quantity provided."}), 400

    try:
        product.quantity = new_quantity
        product.is_available = new_quantity > 0
        db.session.commit()
        return jsonify({"status": "success", "message": "Product quantity updated successfully.", "product": product.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating product quantity: {e}")
        return jsonify({"status": "error", "message": "Failed to update product quantity."}), 500

@app.route('/api/marketplace/products/<int:product_id>', methods=['DELETE'])
@csrf.exempt
@token_required
def delete_product(current_user, product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"status": "error", "message": "Product not found."}), 404
    if product.seller_id != current_user.id:
        return jsonify({"status": "error", "message": "You are not authorized to delete this product."}), 403

    try:
        db.session.delete(product)
        db.session.commit()
        return jsonify({"status": "success", "message": "Product deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting product: {e}")
        return jsonify({"status": "error", "message": "Failed to delete product."}), 500

# --- NEW: CSV Download Endpoint for Transactions ---
@app.route('/api/business-transactions/csv', methods=['GET'])
@token_required
def download_transactions_csv(current_user):
    try:
        transaction_type = request.args.get('type', '')
        start_date_str = request.args.get('startDate', '')

        query = Transaction.query.filter(
            or_(
                Transaction.user_id == current_user.id,
                Transaction.receiver_id == current_user.id
            ),
            or_(
                Transaction.type == 'product_buy',
                Transaction.type == 'product_sell'
            )
        )

        if transaction_type:
            query = query.filter(
                Transaction.type == f'product_{transaction_type}'
            )

        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                query = query.filter(Transaction.timestamp >= start_date)
            except ValueError:
                return jsonify({"status": "error", "message": "Invalid startDate format. Use YYYY-MM-DD."}), 400

        transactions = query.order_by(Transaction.timestamp.desc()).all()

        if not transactions:
            return jsonify({"status": "error", "message": "No transactions found for the specified period."}), 404

        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Type', 'Description', 'Amount', 'Fee', 'Net Amount', 'Status'])

        for tx in transactions:
            amount = float(tx.amount)
            fee = 0.01 * abs(amount) if tx.type == 'product_buy' else 0  # 1% fee for buyers
            net_amount = amount - fee if tx.type == 'product_buy' else amount
            writer.writerow([
                tx.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                tx.type.replace('_', ' ').title(),
                tx.description or 'N/A',
                f"${amount:.2f}",
                f"${fee:.2f}",
                f"${net_amount:.2f}",
                tx.status.title()
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename=transactions_{start_date_str}.csv"}
        )
    except Exception as e:
        print(f"Error generating CSV: {e}")
        return jsonify({"status": "error", "message": "Failed to generate CSV."}), 500
    
@app.cli.command("init-db")
def init_db_command():
    """Initializes the database."""
    db.create_all()
    print('Initialized the database.')

from flask import request, jsonify
import logging
import traceback
import google.generativeai as genai

# Ensure these imports are at the top of your app.py file
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
# Assuming 'User' model is imported from your models.py or defined in app.py
# from .models import User # Or wherever your User model is defined
import google.generativeai as genai # Ensure this is imported and configured


@app.route('/api/chatbot-advice', methods=['POST'])
@csrf.exempt
@jwt_required()
def chatbot_advice():
    try:
        current_user_id = get_jwt_identity()
        current_user = db.session.get(User, current_user_id)
        if not current_user:
            app.logger.error(f"User not found: {current_user_id}")
            return jsonify({"status": "error", "message": "User not found"}), 404

        data = request.get_json()
        user_query = data.get('message')
        chat_history = data.get('chat_history', [])

        if not user_query:
            app.logger.warning("Missing user query in chatbot request")
            return jsonify({"status": "error", "message": "Message is required"}), 400

        model = genai.GenerativeModel("gemini-1.5-flash")
        profile_context = f"""
        User Profile:
        - Name: {current_user.full_name}
        - Email: {current_user.email}
        - Balance: ${float(current_user.balance):.2f}
        - Income Sources: {current_user.income_sources or 'Not provided'}
        - Expenses: {current_user.expenses or 'Not provided'}
        - Debt: {current_user.debt or 'Not provided'}
        - Financial Goals: {current_user.financial_goals or 'Not provided'}
        """
        system_instruction = (
            "You are Nova7's AI Financial Advisor, providing clear, concise, and actionable financial advice. "
            "Use the user's profile and transaction history to personalize responses. "
            "If data is missing, encourage the user to update their profile. "
            "Maintain a professional and empathetic tone."
        )

        recent_transactions = [t.to_dict() for t in Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).limit(5).all()]
        local_context = {
            "location": f"{current_user.city or 'Unknown'}, {current_user.province or 'Unknown'}, {current_user.country}",
            "currency": "USD"
        }

        conversation = [
            {
                "role": "user",
                "parts": [{"text": f"{system_instruction}\n\n{profile_context}\nRecent Transactions: {json.dumps(recent_transactions, indent=2)}\nLocal Context: {json.dumps(local_context, indent=2)}\n\nQuery: {user_query}"}]
            }
        ]
        conversation.extend(chat_history)

        response = model.generate_content(conversation)
        advice = response.candidates[0].content.parts[0].text
        app.logger.info(f"Chatbot advice generated for user {current_user.email}")
        return jsonify({"status": "success", "reply": advice}), 200
    except Exception as e:
        app.logger.error(f"Chatbot error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to generate advice"}), 500

# Other routes like /api/login should follow AFTER the entire chatbot_advice function

# The __main__ block should also be at the very end of your app.py file
if __name__ == '__main__':
    # With Flask-Migrate, direct db.create_all() might be replaced by migration commands
    # For initial setup, you might still use it or run flask db init/migrate/upgrade
    with app.app_context():
        db.create_all()
        # You can add initial data here if needed, e.g., default subscriptions
        if not Subscription.query.first():
            print("Adding default subscriptions...")
            basic_sub = Subscription(name="Basic Insurance", price=10.00, description="Basic coverage.", features={"coverage": "basic"})
            premium_sub = Subscription(name="Premium Insurance", price=25.00, description="Premium coverage with more benefits.", features={"coverage": "premium", "support": "24/7"})
            db.session.add(basic_sub)
            db.session.add(premium_sub)
            db.session.commit()
            print("Default subscriptions added.")
    app.run(debug=True, port=5005, host='0.0.0.0') # Set host to 0.0.0.0 to be accessible externally if needed
    # Trigger redeploy - no logic change