import jwt
import os
from datetime import datetime, timedelta
from flask import current_app

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_jwt_secret_key_here")

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
        if not user_id:
            return None
        return user_id
    except jwt.InvalidTokenError:
        return None
