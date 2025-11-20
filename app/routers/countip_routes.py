from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from ..database import SessionLocal
from .. import auth, models
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header
from typing import Optional
import httpx
import jwt
from ..crud import get_top_5_summary

router = APIRouter(prefix="/api", tags=["dashboard"])

security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user_countip(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = auth.decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@router.get("/top-5-summary")
async def proxy_elastic(current_user: models.User = Depends(get_current_user_countip),
                  db: Session = Depends(get_db)):
     return get_top_5_summary(db)