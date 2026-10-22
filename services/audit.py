import hashlib
from datetime import datetime, timezone
from models import db, AuditLog

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class AuditService:
    @staticmethod
    def _calculate_entry_hash(prev_hash: str, timestamp_str: str, event_type: str,
                              user_id: str, action: str, target: str,
                              status: str, details: str, ip: str) -> str:
        payload = f"{prev_hash}|{timestamp_str}|{event_type}|{user_id}|{action}|{target}|{status}|{details}|{ip}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    @classmethod
    def log_event(cls, event_type: str, action: str, status: str = 'SUCCESS',
                  target_resource: str = None, details: str = None,
                  user = None, ip_address: str = None):
        """
        Appends an immutable, hash-chained security event record.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Get the previous entry's hash
        last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        prev_hash = last_log.entry_hash if last_log else GENESIS_HASH
        
        user_id_val = str(user.id) if user and hasattr(user, 'id') else "0"
        user_email = user.email if user and hasattr(user, 'email') else "system/anonymous"
        user_role = user.role if user and hasattr(user, 'role') else "N/A"
        
        target_val = target_resource or "-"
        details_val = details or "-"
        ip_val = ip_address or "127.0.0.1"
        
        entry_hash = cls._calculate_entry_hash(
            prev_hash=prev_hash,
            timestamp_str=timestamp_str,
            event_type=event_type,
            user_id=user_id_val,
            action=action,
            target=target_val,
            status=status,
            details=details_val,
            ip=ip_val
        )
        
        log_entry = AuditLog(
            timestamp=now,
            event_type=event_type,
            user_id=user.id if user and hasattr(user, 'id') else None,
            user_email=user_email,
            role=user_role,
            ip_address=ip_val,
            action=action,
            target_resource=target_val,
            status=status,
            details=details_val,
            previous_hash=prev_hash,
            entry_hash=entry_hash
        )
        
        db.session.add(log_entry)
        db.session.commit()
        return log_entry

    @classmethod
    def verify_audit_chain(cls):
        """
        Forensically verifies the complete hash chain from genesis block to tip.
        Detects any tampering, alteration, or deletion of log entries.
        """
        logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
        if not logs:
            return {
                'is_valid': True,
                'total_records': 0,
                'broken_at_id': None,
                'message': 'No audit logs found. Chain is empty and clean.'
            }
        
        prev_hash = GENESIS_HASH
        for idx, entry in enumerate(logs):
            # Check 1: Does this record point to the correct previous hash?
            if entry.previous_hash != prev_hash:
                return {
                    'is_valid': False,
                    'total_records': len(logs),
                    'broken_at_id': entry.id,
                    'entry_timestamp': entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'message': f'Tamper alert! Audit record ID #{entry.id} previous_hash mismatch. '
                               f'Expected {prev_hash[:16]}... but found {entry.previous_hash[:16]}...'
                }
            
            # Check 2: Does the record's content match its stored hash?
            timestamp_str = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
            calculated_hash = cls._calculate_entry_hash(
                prev_hash=entry.previous_hash,
                timestamp_str=timestamp_str,
                event_type=entry.event_type,
                user_id=str(entry.user_id) if entry.user_id else "0",
                action=entry.action,
                target=entry.target_resource or "-",
                status=entry.status,
                details=entry.details or "-",
                ip=entry.ip_address or "127.0.0.1"
            )
            
            if calculated_hash != entry.entry_hash:
                return {
                    'is_valid': False,
                    'total_records': len(logs),
                    'broken_at_id': entry.id,
                    'entry_timestamp': entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'message': f'Tamper alert! Audit record ID #{entry.id} content has been modified! '
                               f'Calculated hash {calculated_hash[:16]}... != recorded hash {entry.entry_hash[:16]}...'
                }
            
            prev_hash = entry.entry_hash
            
        return {
            'is_valid': True,
            'total_records': len(logs),
            'broken_at_id': None,
            'message': f'Audit log integrity 100% verified. All {len(logs)} records match the cryptographic hash chain.'
        }
