from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from ..database import SessionLocal
from .. import auth, models
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header
from typing import Optional
import httpx
from ..config import EXTERNAL_ELASTIC_BASE
import jwt

router = APIRouter(prefix="/api", tags=["elastic"])

security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
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

@router.get("/elastic")
async def proxy_elastic(timeframe: str, current_user: models.User = Depends(get_current_user)):
    # Forward request to external elastic endpoint
    url = f"{EXTERNAL_ELASTIC_BASE}/api/threats/counts"
    params = {"timeframe": timeframe}
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url, params=params)
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Error contacting external service: {str(e)}")
    # forward status code and json/text
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        return resp.json()
    else:
        return resp.text

@router.get("/summary")
async def get_ws_url(current_user: models.User = Depends(get_current_user)):
    """
    Menghasilkan WebSocket URL lengkap dengan JWT.
    Frontend bisa memanggil endpoint ini untuk mendapatkan URL WS yang valid.
    """
    token = auth.create_access_token({"sub": current_user.id, "type": "access"})

    ws_url = f"wss://103.150.227.205:8000/api/threats/events/summary/ws?token={token}"

    return {"websocket_url": ws_url}
