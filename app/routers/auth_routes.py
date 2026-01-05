from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import schemas, crud, models, database, utils, auth
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt, time, os

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "rahasia")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

router = APIRouter(prefix="/api/auth", tags=["auth"])

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register", response_model=schemas.UserOut)
def register(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = crud.get_user_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = crud.create_user(db, user_in)
    return user

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    refresh_token: str

@router.post("/login", response_model=LoginResponse)
def login(data: schemas.LoginIn, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not utils.verify_password(data.password, user.pass_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token, access_exp = auth.create_access_token({"sub": str(user.id)})
    refresh_token, refresh_exp = auth.create_refresh_token({"sub": str(user.id)})

    # store refresh token in DB
    crud.create_refresh_token_in_db(db, user.id, refresh_token, refresh_exp)

    return {
        "access_token": access_token,
        "expires_at": access_exp,
        "refresh_token": refresh_token
    }

@router.post("/refresh")
def refresh_token(body: schemas.TokenRefresh, db: Session = Depends(get_db)):
    from .. import auth as _auth
    try:
        payload = _auth.decode_token(body.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    # check refresh token exists in DB
    rt = db.query(models.RefreshToken).filter(models.RefreshToken.token == body.refresh_token).first()
    if not rt:
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    access_token, access_exp = _auth.create_access_token({"sub": str(user_id)})
    return {"access_token": access_token, "expires_at": access_exp}

@router.post("/logout")
def logout(body: schemas.TokenRefresh, db: Session = Depends(get_db)):
    # Revoke single refresh token
    crud.revoke_refresh_token(db, body.refresh_token)
    return {"detail": "Logged out"}

def create_service_token():
    """Token untuk service internal"""
    payload = {
        "type": "service",
        "iss": "main-backend",
        "exp": int(time.time()) + 60  # berlaku 1 menit
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token