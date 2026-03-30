from fastapi import APIRouter, Depends, HTTPException, status, Request, Security
from sqlalchemy.orm import Session
from ..database import SessionLocal
from .. import auth, models
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header
from typing import Optional
import httpx
from ..config import INTERNAL_KEY, SERVICE_URL
import jwt
from fastapi.security import APIKeyHeader

router = APIRouter(prefix="/api", tags=["elastic"])

# Kunci rahasia untuk komunikasi antar service
# INTERNAL_KEY = "RAHASIA_SANGAT_KUAT"

# PASTIKAN PORT INI ADALAH PORT SERVICE BACKEND ANDA (Contoh: 8001)
# Jika Backend Utama jalan di 8000, Service Backend tidak boleh di 8000 juga.
# SERVICE_URL = "http://127.0.0.1:8000" 

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

# --- PROXY ROUTES ---

@router.post("/threats/summary")
async def proxy_threat_summary(
    body: dict, 
    current_user: models.User = Depends(get_current_user)
):
    """Meneruskan request summary ke Service Backend"""
    # Menyiapkan headers
    headers = {
        "X-Internal-Service-Key": INTERNAL_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            # DITAMBAHKAN: parameter headers=headers agar key terkirim
            response = await client.post(
                f"{SERVICE_URL}/api/threats/events/summary",
                json=body,
                headers=headers, 
                timeout=60.0
            )
            
            # Jika ada error dari service (seperti 403), kita ingin lihat detailnya
            if response.status_code != 200:
                print(f"Error dari Service Summary: {response.status_code} - {response.text}")
                try:
                    return response.json()
                except:
                    raise HTTPException(status_code=response.status_code, detail=response.text)
                    
            return response.json()
        except httpx.HTTPError as e:
            raise HTTPException(status_code=500, detail=f"Service Backend Error: {str(e)}")

@router.post("/threats/filter")
async def proxy_threat_filter(
    body: dict, 
    current_user: models.User = Depends(get_current_user)
):
    """Meneruskan request filter ke Service Backend"""
    # 1. Pastikan headers didefinisikan di dalam fungsi
    headers = {
        "X-Internal-Service-Key": INTERNAL_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # 2. Log untuk memastikan fungsi ini terpanggil di Backend Utama
    print(f"--- PROXY FILTER LOG ---")
    print(f"Mengirim ke: {SERVICE_URL}/api/threats/events/filter")

    async with httpx.AsyncClient() as client:
        try:
            # Gunakan method request dengan parameter eksplisit
            response = await client.request(
                method="POST",
                url=f"{SERVICE_URL}/api/threats/events/filter",
                json=body,
                headers=headers,
                timeout=60.0
            )
            
            # Jika service backend memberikan error
            if response.status_code != 200:
                print(f"Error dari Service Filter: {response.status_code} - {response.text}")
                try:
                    return response.json()
                except:
                    return {"error": response.text}
                
            return response.json()
            
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Service Backend tidak aktif/tidak bisa dihubungi")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@router.post("/auth/verify-token")
async def verify_token(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    token = body.get("token")

    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    try:
        payload = auth.decode_token(token)
    except jwt.ExpiredSignatureError:
        return {"valid": False, "reason": "expired"}
    except Exception:
        return {"valid": False, "reason": "invalid"}

    if payload.get("type") != "access":
        return {"valid": False, "reason": "invalid_type"}

    user_id = payload.get("sub")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return {"valid": False, "reason": "user_not_found"}

    return {
        "valid": True,
        "user_id": user_id
    }