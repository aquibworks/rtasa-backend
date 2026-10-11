# app/models/audit.py

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Index
from app.db.session import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(100), nullable=False)  # e.g., SECRET_STORED, SECRET_RECONSTRUCTED, AUTH_LOGIN
    actor_id = Column(String(100), nullable=True)     # User ID or username performing the action
    details = Column(Text, nullable=True)            # JSON or descriptive text of the action
    status = Column(String(20), nullable=False, default="SUCCESS")  # SUCCESS or FAILURE
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Tamper-evident cryptographic hash chain fields
    prev_hash = Column(String(64), nullable=True)    # SHA-256 hash of the previous log record
    current_hash = Column(String(64), nullable=False) # SHA-256 hash of this current record + prev_hash

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_event_type", "event_type"),
    )