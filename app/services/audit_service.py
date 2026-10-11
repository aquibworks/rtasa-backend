# app/services/audit_service.py

import hashlib
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.audit import AuditLog
from app.core.logging import logger

class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        event_type: str,
        actor_id: str = None,
        details: any = None,
        status: str = "SUCCESS"
    ) -> AuditLog:
        """
        Records a tamper-evident audit log linked via SHA-256 hash chaining in real-time.
        """
        try:
            # 1. Get the latest log entry to retrieve the previous hash
            latest_log = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
            prev_hash = latest_log.current_hash if latest_log else "0" * 64

            # 2. Serialize details if provided as dict or list
            if isinstance(details, (dict, list)):
                details_str = json.dumps(details, sort_keys=True)
            else:
                details_str = str(details) if details else ""

            timestamp = datetime.utcnow()
            timestamp_str = timestamp.isoformat()

            # 3. Calculate SHA-256 hash chain: prev_hash + event_type + actor + details + status + timestamp
            raw_data = f"{prev_hash}|{event_type}|{actor_id or 'system'}|{details_str}|{status}|{timestamp_str}"
            current_hash = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()

            # 4. Create and persist the audit record
            new_log = AuditLog(
                event_type=event_type,
                actor_id=actor_id or "system",
                details=details_str,
                status=status,
                timestamp=timestamp,
                prev_hash=prev_hash,
                current_hash=current_hash
            )

            db.add(new_log)
            db.commit()
            db.refresh(new_log)

            logger.info(f"[AUDIT SUCCESS] Recorded live event '{event_type}' (ID: {new_log.id})")
            return new_log

        except Exception as e:
            db.rollback()
            logger.error(f"[AUDIT ERROR] Failed to record audit log: {e}")
            raise

    @staticmethod
    def verify_chain(db: Session) -> tuple[bool, str]:
        """
        Verifies the cryptographic integrity of the entire audit log chain.
        Returns (is_valid: bool, message: str)
        """
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.asc()).all()
        if not logs:
            return True, "Audit log chain is empty."

        expected_prev_hash = "0" * 64

        for log in logs:
            # Check if previous hash pointer matches expected
            if log.prev_hash != expected_prev_hash:
                return False, f"Chain broken at log ID {log.id}: prev_hash mismatch."

            # Re-calculate hash to verify current integrity
            timestamp_str = log.timestamp.isoformat()
            raw_data = f"{log.prev_hash}|{log.event_type}|{log.actor_id}|{log.details or ''}|{log.status}|{timestamp_str}"
            calculated_hash = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()

            if log.current_hash != calculated_hash:
                return False, f"Tampering detected at log ID {log.id}: current_hash mismatch."

            expected_prev_hash = log.current_hash

        return True, "Audit log chain integrity verified successfully."