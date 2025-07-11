from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash
from index import User, db

# Database connection details
DATABASE_URI = "postgresql://nova7:Disaster2024@localhost:5432/nova7_db"

# Create engine and session
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Query the user by email
email_to_reset = "sapiens@ndatabaye.com"
user = session.query(User).filter_by(email=email_to_reset).first()

if user:
    print(f"User found: {user.email}")
    new_password = "Nova7Password2025"
    user.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
    try:
        session.commit()
        print(f"Password for {user.email} has been reset to: {new_password}")
    except Exception as e:
        session.rollback()
        print(f"Error resetting password: {str(e)}")
else:
    print(f"No user found with email: {email_to_reset}")

# Close the session
session.close()

