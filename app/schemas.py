from pydantic import BaseModel, EmailStr
from typing import Optional
from uuid import UUID
from datetime import datetime

class UserCreate(BaseModel):
    nama: str
    email: EmailStr
    password: str
    tipe: Optional[int] = 0

class UserOut(BaseModel):
    id: UUID
    nama: str
    email: EmailStr
    tipe: int
    expired_date: Optional[datetime]
    created_date: Optional[datetime]
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TokenRefresh(BaseModel):
    refresh_token: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str
