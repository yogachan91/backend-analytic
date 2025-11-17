from sqlalchemy import Column, String, BigInteger, TIMESTAMP, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from .database import Base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nama = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    pass_hash = Column("pass", String, nullable=False)  # column name 'pass' per request
    tipe = Column(BigInteger, default=0)
    expired_date = Column(TIMESTAMP(timezone=False))
    created_date = Column(TIMESTAMP(timezone=False), server_default=func.now())

    refresh_tokens = relationship("RefreshToken", back_populates="user")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=False))
    created_at = Column(TIMESTAMP(timezone=False), server_default=func.now())

    user = relationship("User", back_populates="refresh_tokens")
