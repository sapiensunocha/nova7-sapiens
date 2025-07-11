from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DATABASE_URL = os.environ.get('DATABASE_URL_INTERNAL', 'postgresql://nova7:Disaster2024@localhost:5432/nova7_db')

# Define the User model
Base = declarative_base()
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    full_name = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    balance = Column(Float, default=0.0, nullable=False)

# Password hashing
from werkzeug.security import generate_password_hash

# Connect to database
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

try:
    # Find user
    user = session.query(User).filter_by(email='moraliemihigo12@gmail.com').first()
    if user:
        user.password_hash = generate_password_hash('newpassword123', method='pbkdf2:sha256')
        session.commit()
        print("Password for moraliemihigo12@gmail.com reset to 'newpassword123'")
    else:
        print("User moraliemihigo12@gmail.com not found")
except Exception as e:
    print(f"Error: {str(e)}")
finally:
    session.close()