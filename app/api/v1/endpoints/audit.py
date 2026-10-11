# app/api/v1/endpoints/audit.py

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.audit_service import AuditService
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit", tags=["Audit Logs"])

@router.get("/logs", status_code=status.HTTP_200_OK)
def get_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieves real-time chronological audit logs with hash chain data.
    """
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": log.id,
            "event_type": log.event_type,
            "actor_id": log.actor_id,
            "details": log.details,
            "status": log.status,
            "timestamp": log.timestamp.isoformat(),
            "prev_hash": log.prev_hash,
            "current_hash": log.current_hash,
        }
        for log in logs
    ]

@router.get("/verify", status_code=status.HTTP_200_OK)
def verify_audit_chain(db: Session = Depends(get_db)):
    """
    Verifies the SHA-256 cryptographic hash chain integrity of the audit log database.
    """
    is_valid, message = AuditService.verify_chain(db)
    return {
        "chain_valid": is_valid,
        "message": message
    }