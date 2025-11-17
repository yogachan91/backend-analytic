from sqlalchemy.orm import Session
from . import models, schemas, utils
from datetime import datetime, timedelta
from .utils import add_years_to_datetime
from .auth import create_refresh_token
import uuid

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user(db: Session, user_id):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, user_in: schemas.UserCreate):
    hashed = utils.hash_password(user_in.password)
    now = datetime.utcnow()
    expired = add_years_to_datetime(now, 1)
    user = models.User(
        nama=user_in.nama,
        email=user_in.email,
        pass_hash=hashed,
        tipe=user_in.tipe,
        created_date=now,
        expired_date=expired
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def create_refresh_token_in_db(db: Session, user_id, token_str, expires_at):
    rt = models.RefreshToken(user_id=user_id, token=token_str, expires_at=expires_at)
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt

def revoke_refresh_token(db: Session, token_str: str):
    rt = db.query(models.RefreshToken).filter(models.RefreshToken.token == token_str).first()
    if rt:
        db.delete(rt)
        db.commit()
    return True

def revoke_all_refresh_tokens_for_user(db: Session, user_id):
    db.query(models.RefreshToken).filter(models.RefreshToken.user_id == user_id).delete()
    db.commit()
    return True
