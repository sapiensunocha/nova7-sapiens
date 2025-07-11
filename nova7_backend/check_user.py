from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash
from index import User, db
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Database connection details
DATABASE_URI = os.getenv('DATABASE_URL_INTERNAL', os.getenv('DATABASE_URL_INTERNAL_LOCAL'))

# Create engine and session
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Query the user by email
email_to_check = "sapiens@ndatabaye.com"
user = session.query(User).filter_by(email=email_to_check).first()

if user:
    print(f"User found: {user.email}")
    print(f"Full Name: {user.full_name}")
    print(f"Hashed Password: {user.password_hash}")
    print(f"Is Email Verified: {user.is_email_verified}")

    # Test passwords
    passwords_to_test = ["Disaster2024", "password123", "nova7admin"]
    for password in passwords_to_test:
        if check_password_hash(user.password_hash, password):
            print(f"Password match found: {password}")
            break
    else:
        print("No password match found in tested passwords.")
else:
    print(f"No user found with email: {email_to_check}")

# Close the session
session.close()