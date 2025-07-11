import time
from flask import send_from_directory, url_for
import google.generativeai as genai
import os
from dotenv import load_dotenv
import csv
from io import StringIO
import uuid
from flask import Flask, request, jsonify, make_response, Response
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token, JWTManager, jwt_required, get_jwt_identity, decode_token
)
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy import func, JSON, or_ # Ensure JSON is imported if used in models like db.JSON
from sqlalchemy.exc import OperationalError
from google.cloud import storage
import stripe
import logging
from flask_wtf.csrf import CSRFProtect, generate_csrf
from functools import wraps

# TODO: Remove this email disabling for production if emails should be sent
# Temporarily disable email sending to debug "Subject must be a string" error
def disable_email_send(self, message):
    print(f"Email sending disabled - would have sent to {message.recipients} with subject: {message.subject}")
    return None

# Apply the override to Flask-Mail
Mail.send = disable_email_send

# Load .env file
# Assuming index.py is in 'nova7_backend' and .env is in 'nova7_app' (project root)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
dotenv_path = os.path.join(BASE_DIR, '.env')

if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    print(f"Loaded .env file from: {dotenv_path}")
else:
    print(f"Warning: .env file not found at {dotenv_path}. Using environment variables or defaults.")

# Initialize Flask app
app = Flask(__name__)
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# + START: STATIC FILE SERVING - This is the definitive, working code. +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# This variable points to the root of your project folder on Vercel.
PROJECT_ROOT = '/var/task/'

@app.route('/')
def serve_index():
    """Serves the main index.html file."""
    return send_from_directory(PROJECT_ROOT, 'index.html')

@app.route('/<path:path>')
def serve_static_file(path):
    """
    Serves any other static file from the project root (e.g., wallet.html, css/styles.css).
    This is a catch-all and must come after your specific API routes if they don't have a prefix.
    For safety, all of your API routes should start with '/api/'.
    """
    # This prevents users from trying to access files outside the project folder.
    if '..' in path:
        return 'Not Found', 404
    
    # This will find and serve any file requested, like 'wallet.html' or 'css/styles.css'
    return send_from_directory(PROJECT_ROOT, path)

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# + END: STATIC FILE SERVING. Your API routes should come after this.+
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


# Your API routes like @app.route('/api/csrf-token') etc. continue here...

# CORS Configuration
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5500", "http://127.0.0.1:5501", "https://nova7-sapiens-8jzm.vercel.app", # Common local dev ports
    os.environ.get("FRONTEND_URL", "http://localhost:3000"), 
    "https://nova7.vercel.app" # Your Vercel frontend
]
print(f"Allowed CORS origins: {ALLOWED_ORIGINS}")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

# CSRF Protection
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "a_very_strong_and_unique_csrf_secret_key_please_change")
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "another_very_strong_jwt_secret_key_please_change")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 24)))
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_ERROR_MESSAGE_KEY"] = "message"

# SQLAlchemy Configuration
VERCEL_TMP_DIR = '/tmp' if os.environ.get('VERCEL') else os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_INTERNAL', 'postgresql://neondb_owner:npg_KWJLx8l6UiEj@ep-winter-bush-a8i3nb89-pooler.eastus2.azure.neon.tech/neondb?sslmode=require')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('nova7 App', os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME', 'noreply@example.com')))

# Upload folders Configuration
BASE_UPLOAD_DIR = '/tmp/uploads' if os.environ.get('VERCEL') else os.path.join(VERCEL_TMP_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = BASE_UPLOAD_DIR
app.config['PROFILE_UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_DIR, 'profiles')
app.config['MARKETPLACE_UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_DIR, 'marketplace')
app.config['COMMUNITY_UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_DIR, 'community')
ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg', 'gif'} # Renamed for clarity
ALLOWED_EXTENSIONS_DOCS = {'png', 'jpg', 'jpeg', 'pdf'}


# Initialize GCS
# Ensure GOOGLE_APPLICATION_CREDENTIALS points to the JSON key file content or path correctly handled by your environment
# On Vercel, you'd typically set GOOGLE_APPLICATION_CREDENTIALS as an environment variable containing the JSON key itself.
try:
    gcs_credentials = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if gcs_credentials:
        # If gcs_credentials is a path to a file (local dev)
        if os.path.exists(gcs_credentials):
            storage_client = storage.Client.from_service_account_json(gcs_credentials)
        else: # Assume it's the JSON content itself (Vercel)
            # For this to work, gcs_credentials env var must contain the actual JSON string.
            # This part can be tricky and might need adjustment based on how Vercel handles multi-line env vars or if using a temp file.
            # A common pattern is to write the env var content to a temporary file and pass that path.
            # For simplicity here, assuming direct use if not a path, but this might need review for Vercel.
            import json
            from google.oauth2 import service_account
            credentials_info = json.loads(gcs_credentials)
            storage_client = storage.Client(credentials=service_account.Credentials.from_service_account_info(credentials_info))
        
        gcs_bucket_name = os.environ.get("GCS_BUCKET_NAME")
        if gcs_bucket_name:
            bucket = storage_client.bucket(gcs_bucket_name)
            if not bucket.exists():
                logging.error(f"GCS bucket {gcs_bucket_name} does not exist or is not accessible.")
                storage_client = None
                bucket = None
            else:
                print(f"GCS initialized with bucket: {gcs_bucket_name}")
                logging.info(f"Using GCS bucket: {gcs_bucket_name}")
        else:
            logging.error("GCS_BUCKET_NAME environment variable not set.")
            storage_client = None
            bucket = None
    else:
        logging.warning("GOOGLE_APPLICATION_CREDENTIALS environment variable not set. GCS features will be disabled.")
        storage_client = None
        bucket = None
except Exception as e:
    storage_client = None
    bucket = None
    logging.error(f"GCS initialization failed: {str(e)}")
    print(f"GCS initialization failed: {str(e)}")


# Stripe Configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
if not stripe.api_key:
    print("WARNING: STRIPE_SECRET_KEY environment variable not set. Stripe payments will not work.")
elif stripe.api_key.startswith('sk_test_'):
    print("Using Stripe test mode.")
else:
    print("WARNING: Using live STRIPE_SECRET_KEY. Ensure this is intentional for production.")

# Initialize extensions
jwt = JWTManager(app)
db = SQLAlchemy(app)
mail = Mail(app) # Mail instance already created above, this would re-assign. Keeping the first one.

# CSRF Validation Decorator
# TODO: Implement proper CSRF token validation if not relying on global Flask-WTF protection.
def require_csrf_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            csrf_token_header = request.headers.get('X-CSRF-Token')
            if not csrf_token_header:
                return jsonify({"status": "error", "message": "CSRF token missing from headers"}), 403
            # from flask_wtf.csrf import validate_csrf # Example if you want to validate manually
            # try:
            #     validate_csrf(csrf_token_header) # This might need session context
            # except ValidationError:
            #     return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated

# --- Database Models ---
# (Models will start in Part 2)
# --- Database Models (Continued from Part 1) ---

class User(db.Model):
    __tablename__ = 'user' # Explicit table name
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    company_name = db.Column(db.String(150), nullable=True)
    business_name = db.Column(db.String(150), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)
    id_document_url = db.Column(db.String(500), nullable=True) # Consider a more robust URL type if available
    kyc_status = db.Column(db.String(20), default="pending", nullable=False) # e.g., pending, approved, rejected
    role = db.Column(db.String(50), default="user", nullable=False) # e.g., user, admin, helper
    profile_picture_url = db.Column(db.String(500), nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_token = db.Column(db.String(100), nullable=True, unique=True)
    email_verification_token_expires = db.Column(db.DateTime, nullable=True)
    balance = db.Column(db.Float, default=0.0, nullable=False) # Consider Numeric or Decimal for currency
    signature = db.Column(db.String(255), nullable=True)
    address = db.Column(db.String(500), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    transactions = db.relationship("Transaction", backref="user", lazy=True, cascade="all, delete-orphan")
    marketplace_items_sold = db.relationship("MarketplaceItem", foreign_keys="MarketplaceItem.user_id", backref="seller", lazy="dynamic", cascade="all, delete-orphan")
    community_posts = db.relationship("CommunityPost", backref="author", lazy="dynamic", cascade="all, delete-orphan")
    comments_made = db.relationship("Comment", foreign_keys="Comment.user_id", backref="commenter", lazy="dynamic", cascade="all, delete-orphan")
    likes_given = db.relationship("Like", foreign_keys="Like.user_id", backref="liker", lazy="dynamic", cascade="all, delete-orphan")
    
    admin_teams = db.relationship("TeamMembership", foreign_keys="TeamMembership.admin_id", backref="admin_user_profile", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name slightly
    helper_in_teams = db.relationship("TeamMembership", foreign_keys="TeamMembership.helper_id", backref="helper_user_profile", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name slightly
    
    loan_requests_made = db.relationship("LoanRequest", foreign_keys="LoanRequest.requester_id", backref="requester_user", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name
    loan_offers_made = db.relationship("LoanOffer", foreign_keys="LoanOffer.lender_id", backref="lender_user_profile", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name
    
    loan_agreements_as_borrower = db.relationship("LoanAgreement", foreign_keys="LoanAgreement.borrower_id", backref="borrower_detail_user", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name
    loan_agreements_as_lender = db.relationship("LoanAgreement", foreign_keys="LoanAgreement.lender_id", backref="lender_detail_user_profile", lazy="dynamic", cascade="all, delete-orphan")     # Changed backref name
    
    lendable_products_owned = db.relationship("LendableProduct", foreign_keys="LendableProduct.owner_id", backref="product_owner", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name
    product_loan_requests_made = db.relationship("ProductLoanAgreement", foreign_keys="ProductLoanAgreement.borrower_id", backref="product_loan_borrower", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name
    
    withdrawal_requests = db.relationship("WithdrawalRequest", foreign_keys="WithdrawalRequest.user_id", backref="requesting_user", lazy="dynamic", cascade="all, delete-orphan") # Changed backref name

    orders_bought = db.relationship('Order', foreign_keys='Order.buyer_id', backref='buyer_user', lazy='dynamic') # Changed backref name
    orders_sold = db.relationship('Order', foreign_keys='Order.seller_id', backref='seller_user', lazy='dynamic') # Changed backref name

    user_settings = db.relationship('UserSetting', backref='user', uselist=False, cascade="all, delete-orphan")


    def __repr__(self): 
        return f"<User id={self.id} email='{self.email}' name='{self.full_name}'>"
    def to_dict(self):
        return {
        "id": self.id,
        "fullName": self.full_name,
        "email": self.email,
        "companyName": self.company_name,
        "businessName": self.business_name,
        "idNumber": self.id_number,
        "idDocumentUrl": self.id_document_url,
        "kycStatus": self.kyc_status,
        "role": self.role,
        "profilePictureUrl": self.profile_picture_url,
        "isEmailVerified": self.is_email_verified,
        "memberSince": self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
        "balance": self.balance,
        "signature": self.signature,
        "address": self.address,
        "dateOfBirth": self.date_of_birth.strftime('%Y-%m-%d') if self.date_of_birth else None
    }

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)  # e.g., 'income', 'expense', 'deposit', 'withdrawal'
    amount = db.Column(db.Float, nullable=False) # Consider db.Numeric for precision with currency
    category = db.Column(db.String(100), nullable=True) # Make nullable if not always applicable
    date = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
        "id": self.id,
        "user_id": self.user_id,
        "type": self.type,
        "amount": self.amount,
        "category": self.category,
        "date": self.date.strftime('%Y-%m-%d') if self.date else None,
        "description": self.description,
        "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
    }
    def __repr__(self): 
        return f'<Transaction id={self.id} type={self.type} amount={self.amount}>'
    def to_dict(self):
        return {
        "id": self.id,
        "fullName": self.full_name,
        "email": self.email,
        "companyName": self.company_name,
        "businessName": self.business_name,
        "idNumber": self.id_number,
        "idDocumentUrl": self.id_document_url,
        "kycStatus": self.kyc_status,
        "role": self.role,
        "profilePictureUrl": self.profile_picture_url,
        "isEmailVerified": self.is_email_verified,
        "memberSince": self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
        "balance": self.balance,
        "signature": self.signature,
        "address": self.address,
        "dateOfBirth": self.date_of_birth.strftime('%Y-%m-%d') if self.date_of_birth else None
    }

class MarketplaceItem(db.Model):
    __tablename__ = 'marketplace_item'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # Seller ID
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True) # Changed to nullable, can be optional
    category = db.Column(db.String(100), nullable=True) # Changed to nullable
    price = db.Column(db.Float, nullable=False) # Consider db.Numeric
    condition = db.Column(db.String(50), nullable=True)
    image_urls = db.Column(JSON, nullable=True) # List of URLs
    location = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default='active', nullable=False) # e.g., active, inactive, sold
    is_service = db.Column(db.Boolean, default=False, nullable=False)
    quantity = db.Column(db.Integer, nullable=True) # Nullable if not applicable (e.g., for services or unique items)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    orders = db.relationship('Order', backref='marketplace_item_ordered', lazy='dynamic', cascade="all, delete-orphan") # Changed backref

    def to_dict(self): 
        return {
            "id": self.id, 
            "user_id": self.user_id, 
            "seller_name": self.seller.full_name if self.seller else "N/A", 
            "seller_email": self.seller.email if self.seller else None, 
            "title": self.title, 
            "description": self.description, 
            "category": self.category, 
            "price": self.price, 
            "condition": self.condition, 
            "image_urls": self.image_urls or [], 
            "location": self.location, 
            "status": self.status, 
            "is_service": self.is_service, 
            "quantity": self.quantity, 
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None
        }
    def __repr__(self): 
        return f'<MarketplaceItem id={self.id} title="{self.title}">'
    # --- Database Models (Continued from Part 2) ---

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('marketplace_item.id'), nullable=False, index=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # Redundant if item.user_id is seller
    
    quantity_bought = db.Column(db.Integer, nullable=False, default=1)
    total_price = db.Column(db.Float, nullable=False) # Consider db.Numeric
    order_status = db.Column(db.String(50), default='pending_payment', nullable=False) # e.g., pending_payment, paid, shipped, delivered, completed, cancelled
    payment_gateway_reference = db.Column(db.String(200), nullable=True) # e.g., Stripe Payment Intent ID
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationship to ProductTransfer
    transfer_details = db.relationship('ProductTransfer', backref='order_details', uselist=False, cascade="all, delete-orphan") # Changed backref

    # Relationships to User (already defined in User model via backref)
    # buyer = db.relationship('User', foreign_keys=[buyer_id], backref='purchases') # This would be User.orders_bought
    # seller_user_info = db.relationship('User', foreign_keys=[seller_id], backref='sales') # This would be User.orders_sold

    def __repr__(self):
        return f"<Order id={self.id} item_id={self.item_id} buyer_id={self.buyer_id} status='{self.order_status}'>"

class ProductTransfer(db.Model):
    __tablename__ = 'product_transfer'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False, unique=True, index=True) # Each order has one transfer
    
    status = db.Column(db.String(50), default='pending_shipment', nullable=False) # e.g., pending_shipment, shipped, in_transit, delivered
    tracking_info = db.Column(db.String(200), nullable=True) # e.g., tracking number, carrier
    
    commenced_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False) # When transfer process started
    shipped_at = db.Column(db.DateTime, nullable=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    receipt_confirmed_at = db.Column(db.DateTime, nullable=True) # When buyer confirms receipt

    def __repr__(self):
        return f"<ProductTransfer id={self.id} order_id={self.order_id} status='{self.status}'>"

class CommunityPost(db.Model):
    __tablename__ = 'community_post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True) # URL to an image
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    comments = db.relationship('Comment', backref='parent_post', lazy='dynamic', cascade="all, delete-orphan") # Changed backref
    likes = db.relationship('Like', backref='liked_post', lazy='dynamic', cascade="all, delete-orphan") # Changed backref

    def to_dict(self, current_user_id=None):
        is_liked_by_current_user = False
        if current_user_id:
            like = Like.query.filter_by(user_id=current_user_id, post_id=self.id).first()
            if like:
                is_liked_by_current_user = True
        
        return {
            "id": self.id, 
            "user_id": self.user_id, 
            "author_name": self.author.full_name if self.author else "N/A", 
            "author_avatar_url": self.author.profile_picture_url if self.author and self.author.profile_picture_url else None, 
            "content": self.content, 
            "image_url": self.image_url, 
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            "likes_count": self.likes.count(), 
            "comments_count": self.comments.count(), 
            "is_liked_by_current_user": is_liked_by_current_user
        }
    def __repr__(self): 
        return f'<CommunityPost id={self.id} user_id={self.user_id}>'

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id'), nullable=False, index=True)
    
    def to_dict(self): 
        return {
            "id": self.id, 
            "content": self.content, 
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None,
            "user_id": self.user_id, 
            "commenter_name": self.commenter.full_name if self.commenter else "N/A", 
            "commenter_avatar_url": self.commenter.profile_picture_url if self.commenter and self.commenter.profile_picture_url else None, 
            "post_id": self.post_id
        }
    def __repr__(self): 
        return f'<Comment id={self.id} user_id={self.user_id} post_id={self.post_id}>'

class Like(db.Model):
    __tablename__ = 'like'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='uq_user_post_like'),) # Changed name for convention
    
    def __repr__(self): 
        return f'<Like id={self.id} user_id={self.user_id} post_id={self.post_id}>'

class UserSetting(db.Model):
    __tablename__ = 'user_setting'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False, index=True) # user_id should be unique
    # user relationship defined in User model via backref 'user_settings'
    
    language = db.Column(db.String(10), default='en', nullable=False)
    email_notifications_enabled = db.Column(db.Boolean, default=True, nullable=False)
    theme = db.Column(db.String(20), default='system', nullable=False) # e.g., system, light, dark
    
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self): 
        return {
            "user_id": self.user_id, # Added user_id for reference
            "language": self.language, 
            "email_notifications_enabled": self.email_notifications_enabled, 
            "theme": self.theme,
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None
        }
    def __repr__(self):
        return f"<UserSetting user_id={self.user_id} lang='{self.language}'>"
    # --- Database Models (Continued from Part 3) ---

class ResourceCategory(db.Model):
    __tablename__ = 'resource_category'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50), nullable=True) # e.g., FontAwesome class
    description = db.Column(db.String(255), nullable=True)
    
    articles = db.relationship('Article', backref='resource_category_info', lazy='dynamic', cascade="all, delete-orphan") # Changed backref

    def to_dict(self): 
        return {
            "id": self.id, 
            "slug": self.slug, 
            "name": self.name, 
            "icon": self.icon, 
            "description": self.description
        }
    def __repr__(self):
        return f"<ResourceCategory id={self.id} name='{self.name}'>"

class Article(db.Model):
    __tablename__ = 'article'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(200), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    excerpt = db.Column(db.Text, nullable=True)
    content_html = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('resource_category.id'), nullable=False, index=True)
    author_name = db.Column(db.String(100), default="nova7 Team", nullable=False)
    read_time_minutes = db.Column(db.Integer, nullable=True)
    
    published_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    is_published = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self, include_content=False):
        data = {
            "id": self.id, 
            "slug": self.slug, 
            "title": self.title, 
            "excerpt": self.excerpt, 
            "category_slug": self.resource_category_info.slug if self.resource_category_info else None, 
            "category_name": self.resource_category_info.name if self.resource_category_info else None, 
            "author_name": self.author_name, 
            "read_time_minutes": self.read_time_minutes, 
            "published_at": self.published_at.strftime('%Y-%m-%d') if self.published_at else None,
            "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None, # Added updated_at
            "is_published": self.is_published # Added is_published
        }
        if include_content:
            data["content_html"] = self.content_html
        return data
    def __repr__(self):
        return f"<Article id={self.id} title='{self.title}'>"

class LoanRequest(db.Model):
    __tablename__ = 'loan_request'
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount_requested = db.Column(db.Float, nullable=False) # Consider db.Numeric
    reason_summary = db.Column(db.String(255), nullable=False)
    detailed_proposal = db.Column(db.Text, nullable=True)
    preferred_interest_rate = db.Column(db.Float, nullable=True) # Annual rate
    preferred_repayment_terms = db.Column(db.Text, nullable=True) # e.g., "12 months, monthly payments"
    
    target_lender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True) # For direct requests
    is_public_request = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(50), default='pending_offers', nullable=False) # e.g., pending_offers, offers_received, agreement_made, cancelled, completed
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    offers_received = db.relationship('LoanOffer', backref='related_loan_request', lazy='dynamic', cascade="all, delete-orphan") # Changed backref
    agreements_made = db.relationship('LoanAgreement', foreign_keys='LoanAgreement.loan_request_id', backref='originating_loan_request_info', lazy='dynamic', cascade="all, delete-orphan") # Changed backref
    
    target_lender_info = db.relationship('User', foreign_keys=[target_lender_id]) # Changed name

    def __repr__(self):
        return f"<LoanRequest id={self.id} requester_id={self.requester_id} amount={self.amount_requested} status='{self.status}'>"

class LoanOffer(db.Model):
    __tablename__ = 'loan_offer'
    id = db.Column(db.Integer, primary_key=True)
    lender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    loan_request_id = db.Column(db.Integer, db.ForeignKey('loan_request.id'), nullable=False, index=True)
    
    amount_offered = db.Column(db.Float, nullable=False) # Consider db.Numeric
    interest_rate_offered = db.Column(db.Float, nullable=False) # Annual rate
    repayment_terms_offered = db.Column(db.Text, nullable=True)
    message_to_requester = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='pending_acceptance', nullable=False) # e.g., pending_acceptance, accepted, rejected, withdrawn
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationship to LoanAgreement
    resulting_agreement = db.relationship('LoanAgreement', backref='originating_loan_offer_info', uselist=False, cascade="all, delete-orphan") # Changed backref

    def __repr__(self):
        return f"<LoanOffer id={self.id} lender_id={self.lender_id} loan_request_id={self.loan_request_id} status='{self.status}'>"

class LoanAgreement(db.Model):
    __tablename__ = 'loan_agreement'
    id = db.Column(db.Integer, primary_key=True)
    loan_request_id = db.Column(db.Integer, db.ForeignKey('loan_request.id'), nullable=True, index=True) # Can be null if loan didn't originate from a request
    loan_offer_id = db.Column(db.Integer, db.ForeignKey('loan_offer.id'), nullable=True, unique=True, index=True) # Can be null; an offer results in one agreement
    
    lender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    borrower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    principal_amount = db.Column(db.Float, nullable=False) # Consider db.Numeric
    interest_rate = db.Column(db.Float, nullable=False) # Annual rate
    total_repayable_amount = db.Column(db.Float, nullable=False) # Calculated
    repayment_schedule = db.Column(JSON, nullable=True) # e.g., list of {"due_date": "YYYY-MM-DD", "amount_due": X, "status": "pending/paid"}
    status = db.Column(db.String(50), default='active', nullable=False) # e.g., active, fully_repaid, defaulted
    
    agreement_date = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    next_payment_due_date = db.Column(db.Date, nullable=True)
    final_repayment_date = db.Column(db.Date, nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<LoanAgreement id={self.id} lender_id={self.lender_id} borrower_id={self.borrower_id} status='{self.status}'>"

# Note: The more comprehensive versions of LendableProduct, WithdrawalRequest, and TeamMembership will follow.
# The duplicate simpler versions found later in your original index.py will be omitted.
# --- Database Models (Continued from Part 4) ---

class LendableProduct(db.Model): # Ensuring this is the single, comprehensive definition
    __tablename__ = 'lendable_product'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    lending_terms = db.Column(db.Text, nullable=True) # e.g., duration, fees, conditions for lending
    image_urls = db.Column(JSON, nullable=True) # List of URLs
    availability_status = db.Column(db.String(50), default='available', nullable=False) # e.g., available, on_loan, maintenance
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    product_loan_agreements = db.relationship('ProductLoanAgreement', backref='lendable_product_details', lazy='dynamic', cascade="all, delete-orphan") # Changed backref

    def __repr__(self):
        return f"<LendableProduct id={self.id} title='{self.title}' owner_id={self.owner_id}>"

class ProductLoanAgreement(db.Model):
    __tablename__ = 'product_loan_agreement'
    id = db.Column(db.Integer, primary_key=True)
    lendable_product_id = db.Column(db.Integer, db.ForeignKey('lendable_product.id'), nullable=False, index=True)
    borrower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # Denormalized for easier queries, or could rely on product.owner_id
    
    request_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    approval_date = db.Column(db.DateTime, nullable=True)
    loan_start_date = db.Column(db.Date, nullable=True)
    loan_end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(50), default='pending_approval', nullable=False) # e.g., pending_approval, approved, active, returned, cancelled
    agreed_terms = db.Column(db.Text, nullable=True) # Specific terms for this loan instance
    
    # Timestamps for tracking physical exchange if applicable
    borrower_receipt_confirmed_at = db.Column(db.DateTime, nullable=True) # Borrower confirms they received the item
    owner_return_confirmed_at = db.Column(db.DateTime, nullable=True) # Owner confirms item returned

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False) # When the agreement record was created
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<ProductLoanAgreement id={self.id} product_id={self.lendable_product_id} borrower_id={self.borrower_id} status='{self.status}'>"

class WithdrawalRequest(db.Model): # Ensuring this is the single, comprehensive definition
    __tablename__ = 'withdrawal_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False) # Consider db.Numeric
    status = db.Column(db.String(50), default='pending', nullable=False) # e.g., pending, approved, rejected, processed
    request_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    processed_date = db.Column(db.DateTime, nullable=True)
    payment_details = db.Column(JSON, nullable=True) # e.g., {"method": "bank_transfer", "account_number": "...", "bank_name": "..."}
    admin_notes = db.Column(db.Text, nullable=True) # Notes by admin processing the request
    
    # user relationship defined in User model via backref 'withdrawal_requests'

    def __repr__(self):
        return f"<WithdrawalRequest id={self.id} user_id={self.user_id} amount={self.amount} status='{self.status}'>"

class TeamMembership(db.Model):
    __tablename__ = 'team_membership'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # The primary user (admin of the team)
    helper_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # The user invited as a helper
    permissions = db.Column(JSON, nullable=True) # e.g., {"view_transactions": true, "manage_products": false}
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('admin_id', 'helper_id', name='uq_admin_helper_membership'),) # Changed name
    
    # Relationships to User already defined in User model (admin_teams, helper_in_teams)

    def to_dict(self):
        return {
            "id": self.id,
            "admin_id": self.admin_id,
            "helper_id": self.helper_id,
            "helper_name": self.helper_user_profile.full_name if self.helper_user_profile else "N/A", # Adjusted based on User backref
            "helper_email": self.helper_user_profile.email if self.helper_user_profile else "N/A", # Adjusted
            "permissions": self.permissions or [],
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }
    def __repr__(self):
        return f"<TeamMembership admin_id={self.admin_id} helper_id={self.helper_id}>"

# --- Helper Functions & Initial Setup ---

def _build_cors_preflight_response(): # This is the version from index.py
    response = make_response()
    # It's generally better to let Flask-CORS handle OPTIONS requests automatically based on the global config.
    # This custom handler might override or conflict if not perfectly aligned.
    # For now, keeping as it was in index.py.
    # The Access-Control-Allow-Origin header should ideally be dynamic based on request.headers.get('Origin')
    # if that origin is in ALLOWED_ORIGINS.
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers.add("Access-Control-Allow-Origin", origin)
    else:
        # Fallback or don't set if origin not allowed - depends on desired strictness
        response.headers.add("Access-Control-Allow-Origin", os.environ.get("FRONTEND_URL", "https://nova7.vercel.app"))

    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,X-CSRF-Token")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

@app.before_request
@app.before_request
def initial_app_setup():
    if not hasattr(app, '_db_tables_initialized_this_run'):
        try:
            with app.app_context():
                db.create_all()
            print(f"Database tables checked/created against {app.config['SQLALCHEMY_DATABASE_URI']}.")
            with app.app_context():
                seed_initial_data()  # Force seeding for testing
        except Exception as e:
            print(f"Error during initial table creation/seeding: {e}")
        app._db_tables_initialized_this_run = True
    
    # This should ideally be called once at startup, not before every request.
    # For Vercel's serverless environment, it might be okay if instance re-use is limited.
    # ensure_upload_folders_exist() # Moved to be called once at startup if possible, or ensure it's idempotent.

def seed_initial_data():
    # (Seed data logic as provided in index.py, ensure models are defined before calling this)
    with app.app_context(): # Ensure app context for database operations
        try:
            if not ResourceCategory.query.first():
                print("Seeding initial resource categories...")
                default_categories = [
                    ResourceCategory(slug="budgeting", name="Budgeting & Planning", icon="fas fa-calculator", description="Learn to manage your money effectively."),
                    ResourceCategory(slug="growth", name="Business Growth & Funding", icon="fas fa-chart-line", description="Strategies to scale your business."),
                    ResourceCategory(slug="app-help", name="nova7 App Help", icon="fas fa-question-circle", description="Tutorials and FAQs for using nova7.")
                ]
                db.session.add_all(default_categories)
                db.session.commit()

            if not Article.query.first():
                print("Seeding initial articles...")
                budget_cat = ResourceCategory.query.filter_by(slug="budgeting").first()
                growth_cat = ResourceCategory.query.filter_by(slug="growth").first()
                app_help_cat = ResourceCategory.query.filter_by(slug="app-help").first()
                articles_to_add = []
                if budget_cat:
                    articles_to_add.extend([
                        Article(slug="budgeting-basics", title="Creating Your First Business Budget", category_id=budget_cat.id, excerpt="Learn the fundamentals...", content_html="<p>This is detailed content...</p>", read_time_minutes=5, is_published=True),
                        Article(slug="cash-flow-101", title="Understanding Cash Flow", category_id=budget_cat.id, excerpt="Master your cash flow...", content_html="<p>Detailed content about cash flow...</p>", read_time_minutes=7, is_published=True)
                    ])
                if growth_cat:
                    articles_to_add.append(Article(slug="funding-options", title="Exploring Funding Options", category_id=growth_cat.id, excerpt="Discover how to fund...", content_html="<p>Content on funding sources...</p>", read_time_minutes=10, is_published=True))
                if app_help_cat:
                    articles_to_add.append(Article(slug="nova7-quickstart", title="nova7 Quickstart Guide", category_id=app_help_cat.id, excerpt="Get started quickly...", content_html="<p>Your step-by-step guide...</p>", read_time_minutes=4, is_published=True))
                
                if articles_to_add:
                    db.session.add_all(articles_to_add)
                    db.session.commit()
            print("Initial data seeding check complete.")
        except Exception as e:
            db.session.rollback()
            print(f"Error seeding initial data: {e}")

def ensure_upload_folders_exist():
    # This should be called once when the app starts, not before every request.
    # For serverless, this might run on each cold start.
    print("Ensuring upload folders exist...")
    for folder_key in ['PROFILE_UPLOAD_FOLDER', 'MARKETPLACE_UPLOAD_FOLDER', 'COMMUNITY_UPLOAD_FOLDER']:
        if folder_key in app.config:
            folder_path = app.config[folder_key]
            try:
                os.makedirs(folder_path, exist_ok=True)
                # print(f"Upload folder verified/created: {folder_path}")
            except OSError as e:
                print(f"Warning: Could not create upload folder {folder_path}: {e}")
        else:
            print(f"Warning: Upload folder key {folder_key} not in app.config.")

# Call ensure_upload_folders_exist once, e.g. after app initialization,
# but for Vercel, this might need to be in initial_app_setup or handled differently.
# For now, let's assume initial_app_setup covers what's needed for Vercel's /tmp.
# If running locally and VERCEL env var is not set, VERCEL_TMP_DIR will be the script's directory.
# ensure_upload_folders_exist() # Better to call this conditionally or during app factory pattern.

# --- Basic API Routes ---
# --- Static Frontend Serving (FINAL, CORRECTED VERSION) ---

# On Vercel, your project files are always in the '/var/task/' directory.
VERCEL_PROJECT_ROOT = '/var/task/' 

# This route serves your main 'index.html' file
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token_endpoint(): # Renamed to avoid conflicts
    print("CSRF TOKEN REQUEST - INDEX")
    token = generate_csrf()
    origin = request.headers.get('Origin')
    response = jsonify({"status": "success", "csrf_token": token})
    if origin in ALLOWED_ORIGINS:
         response.headers.add("Access-Control-Allow-Origin", origin)
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response, 200

@app.route('/api/test')
def api_test_route(): # Renamed
    return jsonify({'message': 'Test API endpoint from nova7 backend is A-OK!'})

@app.route('/api/send-test-email')
def send_test_email_route(): # Renamed
    # This will use the disable_email_send mock if it's still active
    try:
        msg = Message(
            subject="Test Email from nova7 (index.py)", # Identify source
            recipients=["test@example.com"],
            body="This is a test email from the nova7 backend (index.py)!"
        )
        mail.send(msg) # This will be intercepted by disable_email_send if active
        return jsonify({'status': 'success', 'message': 'Test email processed (check console for mock send).'}), 200
    except Exception as e:
        print(f"Error sending test email: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to send test email: {str(e)}'}), 500

# (Authentication and other feature routes will start in Part 6)
# --- Authentication Routes (Continued from Part 5) ---

@app.route('/api/register', methods=['POST', 'OPTIONS'])
@require_csrf_token
def register_user_endpoint(): # Renamed to avoid conflicts
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Request body must be JSON"}), 400
    
    # Check for required fields based on your comprehensive User model and register.html form
    required_fields = ['fullName', 'email', 'password', 'businessName', 'idNumber'] 
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({"status": "error", "message": f"Missing required fields: {', '.join(missing_fields)}"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"status": "error", "message": "Email already registered"}), 409
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    new_user = User(
        full_name=data['fullName'],
        email=data['email'],
        password_hash=hashed_password,
        company_name=data.get('companyName'),
        business_name=data.get('businessName'),
        id_number=data.get('idNumber'),
        id_document_url=data.get('idDocumentUrl')
        # Other fields like role, is_email_verified, balance, kyc_status use defaults from model
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        # Create default settings for the new user
        user_settings = UserSetting(user_id=new_user.id)
        db.session.add(user_settings)
        db.session.commit()
        print(f"User {new_user.id} registered: {new_user.email} with role '{new_user.role}', email verified: {new_user.is_email_verified}")
        return jsonify({"status": "success", "message": "User registered successfully. Please verify your email."}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error registering user: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to register user due to a server error."}), 500

import logging
from sqlalchemy.exc import OperationalError
logger = logging.getLogger(__name__)

import logging
logger = logging.getLogger(__name__)

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login_user_endpoint():
    if request.method == 'OPTIONS':
        return jsonify({"status": "success"}), 200
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"status": "error", "message": "Email and password required"}), 400
        user = User.query.filter_by(email=data['email']).first()
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        access_token = create_access_token(identity=user.id)
        return jsonify({"status": "success", "access_token": access_token, "user": user.to_dict()}), 200
    except OperationalError as db_err:
        logger.error(f"Database error during login: {str(db_err)}")
        return jsonify({"status": "error", "message": "Database connection issue"}), 500
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": "Server error occurred"}), 500
    
@app.route('/api/db-test', methods=['GET'])
def test_db():
    try:
        db.session.execute('SELECT 1')
        return jsonify({"status": "success", "message": "Database connection OK"}), 200
    except OperationalError as db_err:
        logger.error(f"Database test error: {str(db_err)}")
        return jsonify({"status": "error", "message": str(db_err)}), 500
    except Exception as e:
        logger.error(f"Database test error: {str(e)}")
        return jsonify({"status": "error", "message": "Server error occurred"}), 500

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@jwt_required() # Requires a valid token to "logout" (client clears token)
@require_csrf_token # Good practice for POST even if just a signal
def logout_user_endpoint(): # Renamed
    if request.method == 'OPTIONS': 
        return _build_cors_preflight_response()
    # Server-side an actual logout involves invalidating the token if using a denylist.
    # For simple JWT, client is responsible for discarding the token.
    return jsonify({"status": "success", "message": "Logout successful. Please clear token on client-side."}), 200

@app.route('/api/profile', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_user_profile_endpoint():
    if request.method == 'OPTIONS': 
        return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    if not user: 
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    return jsonify({"status": "success", "user": user.to_dict()}), 200
from flask import send_file
import os

@app.route('/public/profile/<int:user_id>', methods=['GET'])
def public_profile(user_id):
    # Fetch user data without authentication
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Publicly accessible user data (exclude sensitive fields)
    public_user_data = {
        "id": user.id,
        "fullName": user.full_name,
        "dateOfBirth": user.date_of_birth.strftime('%Y-%m-%d') if user.date_of_birth else None,
        "signature": user.signature,
        "address": user.address,
        "profilePictureUrl": user.profile_picture_url,
        "kycStatus": user.kyc_status,
        "memberSince": user.created_at.strftime('%Y-%m-%d') if user.created_at else None,
        # Exclude sensitive fields like email, balance
    }

    # Option 1: Serve profile.html directly with embedded data
    # Save public_user_data to a temporary JSON file or pass via template
    # For simplicity, we'll serve the static profile.html and let client fetch data

    # Option 2: Return JSON for client-side rendering
    if request.headers.get('Accept') == 'application/json':
        return jsonify({"status": "success", "user": public_user_data}), 200

    # Serve profile.html from your frontend directory
    frontend_path = os.path.join(os.path.dirname(__file__), '../frontend')  # Adjust path to your frontend folder
    profile_html_path = os.path.join(frontend_path, 'profile.html')
    if os.path.exists(profile_html_path):
        return send_file(profile_html_path)
    else:
        return jsonify({"status": "error", "message": "Profile page not found"}), 404

@app.route('/api/profile/update', methods=['PUT', 'OPTIONS'])
@csrf.exempt
@jwt_required()
def update_user_profile_endpoint():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()

    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    # Safely update all fields from the settings page
    if 'fullName' in data: user.full_name = data.get('fullName')
    if 'companyName' in data: user.company_name = data.get('companyName')
    if 'role' in data: user.role = data.get('role')
    if 'address' in data: user.address = data.get('address')
    if 'signature' in data: user.signature = data.get('signature')
    if 'profilePictureUrl' in data: user.profile_picture_url = data.get('profilePictureUrl')

    if data.get('dateOfBirth'):
        try:
            user.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        except (ValueError, TypeError):
            pass # Ignore invalid date formats from the frontend

    try:
        db.session.commit()
        return jsonify(status="success", message="Profile updated successfully", user=user.to_dict())
    except Exception as e:
        db.session.rollback()
        print(f"Error updating profile for user {user_id}: {str(e)}")
        return jsonify({"status": "error", "message": "Database error while saving."}), 500
@app.route('/api/email/request-verification', methods=['POST', 'OPTIONS'])
@jwt_required()
@require_csrf_token
def request_email_verification_endpoint(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    if not user: return jsonify({"status": "error", "message": "User not found"}), 404
    if user.is_email_verified: return jsonify({"status": "info", "message": "Email is already verified"}), 200
    
    try:
        verification_token = str(uuid.uuid4())
        user.email_verification_token = verification_token
        user.email_verification_token_expires = datetime.now(timezone.utc) + timedelta(hours=24)
        db.session.commit()
        
        frontend_base_url = "https://nova7-sapiens-8jzm.vercel.app" # Adjusted default to 5501
        verification_url = f"{frontend_base_url}/verify-email.html?token={verification_token}"
        msg_body = f"Hi {user.full_name},\n\nPlease verify your email address for nova7 by clicking the link below:\n{verification_url}\n\nThis link is valid for 24 hours.\n\nThanks,\nThe nova7 Team"
        msg = Message(subject="Verify Your Email Address - nova7", recipients=[user.email], body=msg_body)
        mail.send(msg) # This will use the mock if Mail.send is still overridden
        return jsonify({"status": "success", "message": "Verification email sent. Please check your inbox."}), 200
    except Exception as e:
        db.session.rollback() # Rollback potential commit of token if email fails
        print(f"Error sending verification email for user {user.email}: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to send verification email."}), 500

@app.route('/api/email/verify/<string:token>', methods=['GET', 'OPTIONS']) # Added string type for token
def verify_email_endpoint(token): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    if not token: return jsonify({"status": "error", "message": "Verification token is missing."}), 400
    
    user = User.query.filter_by(email_verification_token=token).first()
    if not user: return jsonify({"status": "error", "message": "Invalid or expired verification token."}), 400 # Or 404
    
    # Ensure token_expires is timezone-aware if comparing with timezone-aware now()
    token_expiration = user.email_verification_token_expires.replace(tzinfo=timezone.utc) if user.email_verification_token_expires.tzinfo is None else user.email_verification_token_expires

    if token_expiration < datetime.now(timezone.utc):
        user.email_verification_token = None # Clear expired token
        user.email_verification_token_expires = None
        db.session.commit()
        return jsonify({"status": "error", "message": "Verification token has expired. Please request a new one."}), 400
    
    user.is_email_verified = True
    user.email_verification_token = None
    user.email_verification_token_expires = None
    try:
        db.session.commit()
        return jsonify({"status": "success", "message": "Email verified successfully! You can now log in."}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error verifying email with token {token}: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to verify email due to server error."}), 500

@app.route('/api/password/forgot', methods=['POST', 'OPTIONS'])
@require_csrf_token # CSRF for POST
def forgot_password_endpoint(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    data = request.get_json()
    if not data or not data.get('email'): return jsonify({"status": "error", "message": "Email is required"}), 400
    
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user: # Only send if user exists, but message is generic to prevent user enumeration
        try:
            # Create a short-lived token specifically for password reset
            reset_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30), additional_claims={"type": "password_reset"})
            frontend_base_url = "https://nova7-sapiens-8jzm.vercel.app" # Adjusted default
            reset_url = f"{frontend_base_url}/reset-password.html?token={reset_token}"
            msg = Message(subject="Password Reset Request for nova7", recipients=[user.email],
                          body=f"Hi {user.full_name},\n\nPlease click the link below to reset your password:\n{reset_url}\n\nThis link is valid for 30 minutes.\n\nIf you did not request this, please ignore this email.\n\nThanks,\nThe nova7 Team")
            mail.send(msg)
        except Exception as e:
            print(f"Error sending password reset email to {email}: {str(e)}")
            # Still return a generic success message to prevent leaking info about email send failure
    
    return jsonify({"status": "success", "message": "If an account with that email exists, a password reset link has been sent."}), 200

@app.route('/api/password/reset', methods=['POST', 'OPTIONS'])
@require_csrf_token # CSRF for POST
def reset_password_endpoint(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "No data provided"}), 400
    
    token = data.get('token')
    new_password = data.get('newPassword')
    if not token or not new_password: 
        return jsonify({"status": "error", "message": "Token and new password are required"}), 400
    if len(new_password) < 8: 
        return jsonify({"status": "error", "message": "Password must be at least 8 characters long"}), 400
        
    try:
        decoded_token = decode_token(token)
        if decoded_token.get("type") != "password_reset":
            return jsonify({"status": "error", "message": "Invalid token type for password reset"}), 401 # Or 400
        
        user_id = decoded_token['sub'] # 'sub' is standard claim for subject (user_id here)
        user = db.session.get(User, user_id)
        if not user: 
            return jsonify({"status": "error", "message": "User not found or token invalid"}), 404 # Or 400
            
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        return jsonify({"status": "success", "message": "Password has been reset successfully. Please log in."}), 200
    except ExpiredSignatureError:
        return jsonify({"status": "error", "message": "Password reset token has expired."}), 401
    except InvalidTokenError: # Catches various JWT decoding errors
        return jsonify({"status": "error", "message": "Invalid or malformed password reset token."}), 401
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting password with token {token}: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to reset password due to a server error."}), 500

# --- Transaction Routes (Copied from index.py, ensure Transaction model is defined) ---
@app.route('/api/transactions/add', methods=['POST', 'OPTIONS'])
@jwt_required()
@require_csrf_token
def add_transaction_route(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "No input data provided"}), 400
    
    transaction_type = data.get('transactionType')
    amount_str = data.get('amount')
    category = data.get('category')
    date_str = data.get('date') # Expects YYYY-MM-DD
    description = data.get('description')

    if not all([transaction_type, amount_str, category, date_str]):
        return jsonify({"status": "error", "message": "Missing required fields (type, amount, category, date)"}), 400
    
    try:
        amount = float(amount_str)
        if amount <= 0: return jsonify({"status": "error", "message": "Amount must be positive"}), 400
        transaction_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid amount or date format (YYYY-MM-DD)"}), 400
    
    if transaction_type not in ['income', 'expense']:
        return jsonify({"status": "error", "message": "Invalid transaction type (must be 'income' or 'expense')"}), 400
        
    new_transaction = Transaction(
        user_id=current_user_id, 
        type=transaction_type, 
        amount=amount, 
        category=category, 
        date=transaction_date, 
        description=description
    )
    try:
        db.session.add(new_transaction)
        db.session.commit()
        return jsonify({"status": "success", "message": f"{transaction_type.capitalize()} added successfully!", "transaction": new_transaction.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error adding transaction for user {current_user_id}: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to add transaction due to a server error."}), 500

@app.route('/api/transactions', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_transactions_route(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    
    args = request.args
    start_date_str = args.get('start_date')
    end_date_str = args.get('end_date')
    transaction_type_filter = args.get('type')
    category_filter = args.get('category')
    description_search = args.get('description_search')
    
    query = Transaction.query.filter_by(user_id=current_user_id)
    
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            query = query.filter(Transaction.date >= start_date)
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            query = query.filter(Transaction.date <= end_date)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid date format. Please use YYYY-MM-DD."}), 400
        
    if transaction_type_filter:
        query = query.filter(Transaction.type == transaction_type_filter)
    if category_filter:
        query = query.filter(Transaction.category == category_filter)
    if description_search:
        query = query.filter(Transaction.description.ilike(f'%{description_search}%'))
        
    user_transactions = query.order_by(Transaction.date.desc(), Transaction.created_at.desc()).all()
    transactions_list = [transaction.to_dict() for transaction in user_transactions]
    return jsonify({"status": "success", "transactions": transactions_list}), 200

@app.route('/api/transactions/<int:transaction_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@jwt_required()
@require_csrf_token # For PUT, DELETE
def manage_transaction_route(transaction_id): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    
    transaction = Transaction.query.filter_by(id=transaction_id, user_id=current_user_id).first()
    if not transaction:
        return jsonify({"status": "error", "message": "Transaction not found or unauthorized"}), 404
        
    if request.method == 'GET':
        return jsonify({"status": "success", "transaction": transaction.to_dict()}), 200
        
    elif request.method == 'PUT':
        data = request.get_json()
        if not data: return jsonify({"status": "error", "message": "No input data provided"}), 400
        
        if 'transactionType' in data:
            if data['transactionType'] not in ['income', 'expense']:
                return jsonify({"status": "error", "message": "Invalid transaction type"}), 400
            transaction.type = data['transactionType']
        if 'amount' in data:
            try:
                amount = float(data['amount'])
                if amount <= 0: return jsonify({"status": "error", "message": "Amount must be positive"}), 400
                transaction.amount = amount
            except ValueError: return jsonify({"status": "error", "message": "Invalid amount format"}), 400
        if 'category' in data:
            transaction.category = data['category']
        if 'date' in data:
            try:
                transaction.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError: return jsonify({"status": "error", "message": "Invalid date format"}), 400
        if 'description' in data:
            transaction.description = data.get('description', transaction.description) # Allow clearing description
            
        try:
            db.session.commit()
            return jsonify({"status": "success", "message": "Transaction updated successfully!", "transaction": transaction.to_dict()}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating transaction {transaction_id}: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to update transaction due to a server error."}), 500
            
    elif request.method == 'DELETE':
        try:
            db.session.delete(transaction)
            db.session.commit()
            return jsonify({"status": "success", "message": "Transaction deleted successfully!"}), 200 # Or 204 No Content
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting transaction {transaction_id}: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to delete transaction due to a server error."}), 500
    
    return jsonify({"status":"error", "message":"Method not allowed"}), 405


@app.route('/api/transactions/download', methods=['GET', 'OPTIONS'])
@jwt_required()
def download_transactions_route(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    user_transactions = Transaction.query.filter_by(user_id=current_user_id).order_by(Transaction.date.asc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Date', 'Type', 'Category', 'Description', 'Amount'])
    for tx in user_transactions:
        cw.writerow([tx.date.strftime('%Y-%m-%d') if tx.date else '', tx.type, tx.category, tx.description or '', tx.amount])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=transactions.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# --- Dashboard Summary Route (already added in previous iteration, ensure it's present and correct) ---
@app.route('/api/dashboard/summary', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_dashboard_summary_endpoint(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    
    total_income = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user_id, Transaction.type == 'income'
    ).scalar() or 0.0
    total_expenses = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user_id, Transaction.type == 'expense'
    ).scalar() or 0.0
    
    net_balance = total_income - total_expenses
    profit_margin = (net_balance / total_income * 100) if total_income > 0 else 0.0
    
    overdue_invoices_amount = 0.0 # Placeholder
    overdue_invoices_count = 0    # Placeholder

    summary_data = {
        "totalIncome": round(total_income, 2), "totalExpenses": round(total_expenses, 2),
        "netBalance": round(net_balance, 2), "profitMargin": round(profit_margin, 1), # Consistent with index.html
        "overdueInvoicesAmount": round(overdue_invoices_amount, 2),
        "overdueInvoicesCount": overdue_invoices_count
    }
    return jsonify({"status": "success", "summary": summary_data}), 200

# --- Reports Routes (Copied from index.py) ---
@app.route('/api/reports/income-expense', methods=['GET', 'OPTIONS'])
@jwt_required()
def income_expense_report_endpoint(): # Renamed
    # ... (Implementation from index.py, ensure Transaction model is used correctly) ...
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    # ... (rest of the logic as in index.py)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    query_income = db.session.query(func.sum(Transaction.amount)).filter_by(user_id=current_user_id, type='income')
    query_expenses = db.session.query(func.sum(Transaction.amount)).filter_by(user_id=current_user_id, type='expense')
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            query_income = query_income.filter(Transaction.date >= start_date)
            query_expenses = query_expenses.filter(Transaction.date >= start_date)
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            query_income = query_income.filter(Transaction.date <= end_date)
            query_expenses = query_expenses.filter(Transaction.date <= end_date)
    except ValueError: return jsonify({"status": "error", "message": "Invalid date format. Please use YYYY-MM-DD."}), 400
    total_income = query_income.scalar() or 0.0
    total_expenses = query_expenses.scalar() or 0.0
    net_profit_loss = total_income - total_expenses
    report_data = {"totalIncome": round(total_income, 2), "totalExpenses": round(total_expenses, 2), "netProfitLoss": round(net_profit_loss, 2), "period": {"start_date": start_date_str if start_date_str else "All Time", "end_date": end_date_str if end_date_str else "All Time"}}
    return jsonify({"status": "success", "report": report_data}), 200


@app.route('/api/reports/category-spending', methods=['GET', 'OPTIONS'])
@jwt_required()
def category_spending_report_endpoint(): # Renamed
    # ... (Implementation from index.py, ensure Transaction model is used correctly) ...
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    # ... (rest of the logic as in index.py)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    query = db.session.query(Transaction.category, func.sum(Transaction.amount).label('total_spent')).filter_by(user_id=current_user_id, type='expense')
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            query = query.filter(Transaction.date >= start_date)
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            query = query.filter(Transaction.date <= end_date)
    except ValueError: return jsonify({"status": "error", "message": "Invalid date format. Please use YYYY-MM-DD."}), 400
    category_spending = query.group_by(Transaction.category).order_by(func.sum(Transaction.amount).desc()).all()
    report_data = [{"category": category, "total_spent": round(total, 2)} for category, total in category_spending]
    return jsonify({"status": "success", "report": report_data, "period": {"start_date": start_date_str if start_date_str else "All Time", "end_date": end_date_str if end_date_str else "All Time"}}), 200


# --- Placeholder for other routes from index.py (Marketplace, Community, Team, Chat, Settings, Resources, Uploads) ---
# These would need their respective models (MarketplaceItem, Order, CommunityPost, etc.) fully defined
# and their route logic copied/adapted carefully. For brevity, only a few key ones were fully fleshed out above.
# Example for one more to show the pattern:
@app.route('/api/settings', methods=['GET', 'PUT', 'OPTIONS'])
@app.route('/api/wallet/balance', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_wallet_balance():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "balance": user.balance}), 200
# =============================================================================

@app.route('/api/settings', methods=['GET', 'PUT'])
@csrf.exempt
@jwt_required()
def settings_endpoint():
        user_id = get_jwt_identity()
        settings = UserSetting.query.filter_by(user_id=int(user_id)).first()
        if not settings:
            settings = UserSetting(user_id=int(user_id))
            db.session.add(settings)
            db.session.commit()
        
        if request.method == 'GET':
            return jsonify({"status": "success", "settings": settings.to_dict()})
        
        elif request.method == 'PUT':
            data = request.get_json()
            if 'language' in data: settings.language = data['language']
            if 'email_notifications_enabled' in data: settings.email_notifications_enabled = bool(data['email_notifications_enabled'])
            if 'theme' in data: settings.theme = data['theme']
            db.session.commit()
            return jsonify(status="success", message="Settings updated", settings=settings.to_dict())

@app.route('/api/wallet/withdrawal', methods=['POST'])
@csrf.exempt
@jwt_required()
def request_withdrawal_endpoint():
        user_id = get_jwt_identity()
        data = request.get_json()
        amount = data.get('amount')
        # Placeholder: In a real app, you would save this WithdrawalRequest to the database
        print(f"User {user_id} requested withdrawal of ${amount}")
        return jsonify(status="success", message="Withdrawal request submitted for review.")

    # --- Other Account Management Routes ---
    
@app.route('/api/profile/change-password', methods=['POST'])
@csrf.exempt
@jwt_required()
def change_password_endpoint():
        user = db.session.get(User, int(get_jwt_identity()))
        data = request.get_json()
        if not user or not check_password_hash(user.password_hash, data.get('currentPassword')):
            return jsonify({"status": "error", "message": "Incorrect current password"}), 401
        
        new_password = data.get('newPassword')
        if not new_password or len(new_password) < 8:
            return jsonify({"status": "error", "message": "New password must be at least 8 characters"}), 400
            
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({"status": "success", "message": "Password updated successfully"})

@app.route('/api/resend-verification', methods=['POST'])
@csrf.exempt
@jwt_required()
def resend_verification_endpoint():
        # Placeholder: Add your full email resend logic here
        print(f"Resending verification for user {get_jwt_identity()}")
        return jsonify(status="success", message="Verification email sent.")

@app.route('/api/profile/delete', methods=['DELETE'])
@csrf.exempt
@jwt_required()
def delete_account_endpoint():
        user = db.session.get(User, int(get_jwt_identity()))
        if user:
            db.session.delete(user)
            db.session.commit()
        return jsonify(status="success", message="Account deleted successfully.")

    # --- File Serving Route ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # --- File Upload Route ---
@app.route('/api/profile/upload-picture', methods=['POST', 'OPTIONS'])
@csrf.exempt
@jwt_required()
def handle_profile_picture_upload():
        if request.method == 'OPTIONS': return _build_cors_preflight_response()
        user_id = get_jwt_identity()
        if 'profilePicture' not in request.files: return jsonify(status="error", message="No file part"), 400
        file = request.files['profilePicture']
        if file and file.filename and allowed_file(file.filename, ALLOWED_EXTENSIONS_IMAGES):
            filename = secure_filename(file.filename)
            unique_filename = f"user_{user_id}_{int(time.time())}_{filename}"
            if bucket:
                gcs_path = f"profiles/{unique_filename}"
                blob = bucket.blob(gcs_path)
                blob.upload_from_file(file, content_type=file.content_type)
                file_url = blob.public_url
            else:
                file_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                file_url = url_for('uploaded_file', filename=f'profiles/{unique_filename}', _external=True)
            return jsonify(status="success", url=file_url)
        return jsonify(status="error", message="Invalid file type"), 400

    # --- Chatbot Route ---
@app.route('/api/chat', methods=['POST', 'OPTIONS'])
@csrf.exempt
@jwt_required()
def handle_chat_message():
        if request.method == 'OPTIONS': return _build_cors_preflight_response()
        data = request.get_json()
        if not data or 'message' not in data: return jsonify(status="error", message="No message in request"), 400
        try:
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
            model = genai.GenerativeModel('gemini-1.5-flash')
            chat_session = model.start_chat(history=data.get('chat_history', []))
            response_stream = chat_session.send_message(data['message'], stream=True)
            def generate():
                for chunk in response_stream:
                    if chunk.text: yield chunk.text
            return Response(generate(), mimetype='text/plain')
        except Exception as e:
            return jsonify(status="error", message="Error with AI service"), 500

@jwt_required()
@require_csrf_token # For PUT
def user_settings_endpoint(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id = get_jwt_identity()
    # Ensure UserSetting model is defined
    settings = UserSetting.query.filter_by(user_id=current_user_id).first()
    if not settings: # Create default settings if none exist for the user
        settings = UserSetting(user_id=current_user_id)
        db.session.add(settings)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error creating default settings for user {current_user_id}: {e}")
            return jsonify({"status": "error", "message": "Could not initialize settings"}), 500
            
    if request.method == 'GET':
        return jsonify({"status": "success", "settings": settings.to_dict()}), 200
    elif request.method == 'PUT':
        data = request.get_json()
        if not data: return jsonify({"status": "error", "message": "No data provided"}), 400
        if 'language' in data: settings.language = data['language']
        if 'email_notifications_enabled' in data: settings.email_notifications_enabled = bool(data['email_notifications_enabled'])
        if 'theme' in data: settings.theme = data['theme']
        try:
            db.session.commit()
            return jsonify({"status": "success", "message": "Settings updated", "settings": settings.to_dict()}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating settings for user {current_user_id}: {e}")
            return jsonify({"status": "error", "message": "Failed to update settings"}), 500

# Utility functions for uploads (ensure ALLOWED_EXTENSIONS_IMAGES/DOCS are defined)
def allowed_file(filename, allowed_extensions_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions_set

@app.route('/api/upload/image', methods=['POST', 'OPTIONS'])
@jwt_required()
@require_csrf_token
def upload_image_route(): # Renamed
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    if not bucket: return jsonify({"status": "error", "message": "GCS Bucket not configured."}), 503 # Service unavailable
    if 'file' not in request.files: return jsonify({"status": "error", "message": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '': return jsonify({"status": "error", "message": "No selected file"}), 400
    
    if file and allowed_file(file.filename, ALLOWED_EXTENSIONS_IMAGES):
        original_filename = secure_filename(file.filename)
        unique_filename = str(uuid.uuid4()) + "_" + original_filename
        context_folder = request.form.get('context', 'general_uploads') # Get context from form data
        
        # Basic security check on context_folder to prevent path traversal if it's user-supplied
        safe_context_folder = "".join(c if c.isalnum() or c in ['_','-'] else "" for c in context_folder)
        if not safe_context_folder: safe_context_folder = 'general_uploads'

        gcs_path = f"{safe_context_folder}/{unique_filename}"
        
        try:
            blob = bucket.blob(gcs_path)
            blob.upload_from_file(file, content_type=file.content_type) # Use upload_from_file
            # blob.make_public() # Consider if all uploads should be public by default
            public_url = blob.public_url # This URL might only work if bucket/object is public
            
            # For signed URLs (if objects are private):
            # signed_url = blob.generate_signed_url(version="v4", expiration=timedelta(minutes=15), method="GET")

            return jsonify({"status": "success", "message": "Image uploaded successfully", "imageUrl": public_url}), 201
        except Exception as e:
            print(f"Error uploading image to GCS: {str(e)}")
            return jsonify({"status": "error", "message": f"Failed to upload image: {str(e)}"}), 500
    return jsonify({"status": "error", "message": "File type not allowed for images"}), 400
# --- Marketplace Routes ---
@app.route('/api/marketplace/items', methods=['GET', 'OPTIONS'])
def get_marketplace_items_endpoint():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    search_term = request.args.get('search')
    category_filter = request.args.get('category')
    sort_by = request.args.get('sort', 'newest')
    
    query = MarketplaceItem.query.filter_by(status='active')
    if search_term:
        query = query.filter(or_(MarketplaceItem.title.ilike(f'%{search_term}%'), MarketplaceItem.description.ilike(f'%{search_term}%')))
    if category_filter:
        query = query.filter_by(category=category_filter)
    if sort_by == 'price_low_high':
        query = query.order_by(MarketplaceItem.price.asc())
    elif sort_by == 'price_high_low':
        query = query.order_by(MarketplaceItem.price.desc())
    else: # Default to newest
        query = query.order_by(MarketplaceItem.created_at.desc())
        
    try:
        paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)
        items_list = [item.to_dict() for item in paginated_items.items]
        return jsonify({
            "status": "success", 
            "items": items_list, 
            "total_items": paginated_items.total,
            "total_pages": paginated_items.pages, 
            "current_page": paginated_items.page,
            "has_next": paginated_items.has_next, 
            "has_prev": paginated_items.has_prev
        }), 200
    except Exception as e:
        print(f"Error fetching marketplace items: {str(e)}")
        return jsonify({"status": "error", "message": "Could not retrieve marketplace items."}), 500
# --- Community Routes ---
@app.route('/api/community/posts', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required() 
@require_csrf_token
def community_posts_endpoint():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()

    current_user_id_str = get_jwt_identity()
    try:
        current_user_id = int(current_user_id_str)
    except ValueError:
        return jsonify(status="error", message="Invalid user ID format in token"), 400

    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        try:
            paginated_posts = CommunityPost.query.order_by(CommunityPost.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
            posts_list = [post.to_dict(current_user_id=current_user_id) for post in paginated_posts.items]
            return jsonify({
                "status": "success", 
                "posts": posts_list,
                "total_posts": paginated_posts.total, 
                "total_pages": paginated_posts.pages,
                "current_page": paginated_posts.page, 
                "has_next": paginated_posts.has_next,
                "has_prev": paginated_posts.has_prev
            }), 200
        except Exception as e:
            print(f"Error fetching community posts: {str(e)}")
            return jsonify({"status": "error", "message": "Could not retrieve community posts."}), 500

    elif request.method == 'POST':
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({"status": "error", "message": "Post content is required"}), 400
        
        content = data.get('content')
        image_url = data.get('imageUrl')
        new_post = CommunityPost(user_id=current_user_id, content=content, image_url=image_url)
        try:
            db.session.add(new_post)
            db.session.commit()
            return jsonify({
                "status": "success", 
                "message": "Post created successfully!", 
                "post": new_post.to_dict(current_user_id=current_user_id)
            }), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error creating community post: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to create post."}), 500
# --- Chatbot Route (FINAL, STREAMING VERSION) ---
@app.route('/api/resources/categories', methods=['GET', 'OPTIONS'])
def get_resource_categories():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    try:
        categories = ResourceCategory.query.all()
        categories_list = [category.to_dict() for category in categories]
        return jsonify({"status": "success", "categories": categories_list}), 200
    except Exception as e:
        print(f"Error fetching resource categories: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to fetch categories"}), 500
@app.route('/api/resources/articles', methods=['GET', 'OPTIONS'])
def get_resource_articles():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    try:
        category_slug = request.args.get('category')
        search_term = request.args.get('search')
        query = Article.query.filter_by(is_published=True)
        if category_slug:
            category = ResourceCategory.query.filter_by(slug=category_slug).first()
            if category:
                query = query.filter_by(category_id=category.id)
            else:
                return jsonify({"status": "success", "articles": []}), 200
        if search_term:
            query = query.filter(or_(Article.title.ilike(f'%{search_term}%'), Article.excerpt.ilike(f'%{search_term}%')))
        articles = query.order_by(Article.published_at.desc()).all()
        articles_list = [article.to_dict() for article in articles]
        return jsonify({"status": "success", "articles": articles_list}), 200
    except Exception as e:
        print(f"Error fetching articles: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to fetch articles"}), 500
@app.errorhandler(Exception)
def handle_error(e):
    logger.error(f"Unhandled error: {str(e)}")
    return jsonify({"status": "error", "message": "Internal server error"}), 500
# --- Main Execution ---
if __name__ == '__main__':
    # Ensure upload folders are ready when the server starts
    ensure_upload_folders_exist()

    port = int(os.environ.get("PORT", 5005))
    app.run(debug=True, host='0.0.0.0', port=port)