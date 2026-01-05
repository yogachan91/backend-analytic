from datetime import datetime, timedelta
import jwt, time, os
from .config import JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from typing import Optional

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expire

def create_refresh_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expire

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except Exception as e:
        raise

# def create_service_token(expires_delta: Optional[timedelta] = None):
#     to_encode = {
#         "type": "service",
#         "iss": "main-backend"
#     }

#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=5)

#     to_encode.update({"exp": expire})

#     encoded_jwt = jwt.encode(
#         to_encode,
#         JWT_SECRET_KEY,
#         algorithm=JWT_ALGORITHM
#     )

#     return encoded_jwt

def create_service_token(exp_seconds=60):
    """
    Generate service token untuk akses service internal
    """
    payload = {
        "type": "service",
        "iss": "main-backend",
        "exp": int(time.time()) + exp_seconds
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

