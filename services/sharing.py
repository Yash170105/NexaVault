import secrets
import json
from datetime import datetime, timezone, timedelta
from models import db, SharingRequest, SharingGrant, Patient, Doctor, MedicalRecord, User
from services.audit import AuditService

class SharingService:
    @classmethod
    def create_request(cls, requesting_doctor: Doctor, patient_id: str,
                       recipient_doctor_id: str, record_ids: list,
                       reason: str, user: User, ip_address: str = "127.0.0.1"):
        """
        Creates a patient-consent-gated sharing request for specific medical records.
        """
        req_id = f"REQ-{secrets.token_hex(6).upper()}"
        req = SharingRequest(
            request_id=req_id,
            patient_id=patient_id,
            requesting_doctor_id=requesting_doctor.doctor_id,
            recipient_doctor_id=recipient_doctor_id,
            record_ids_json=json.dumps(record_ids),
            status='Pending_Consent',
            reason=reason,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(req)
        db.session.commit()
        
        AuditService.log_event(
            event_type='SHARING_REQUEST_CREATED',
            action=f"Requested records for Patient {patient_id}",
            status='SUCCESS',
            target_resource=f"Request: {req_id}",
            details=f"Requester: {requesting_doctor.full_name} | Recipient: {recipient_doctor_id} | Records: {record_ids}",
            user=user,
            ip_address=ip_address
        )
        return req

    @classmethod
    def approve_request(cls, request_id_val: str, patient_user: User,
                        expiry_hours: int = 48, ip_address: str = "127.0.0.1"):
        """
        Patient grants consent, issuing a cryptographically secure, revocable token.
        """
        req = SharingRequest.query.filter_by(request_id=request_id_val).first()
        if not req:
            raise ValueError("Sharing request not found.")
            
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=expiry_hours)
        token = secrets.token_urlsafe(32)
        
        grant = SharingGrant(
            grant_token=token,
            sharing_request_id=req.id,
            patient_id=req.patient_id,
            grantor_doctor_id=req.requesting_doctor_id,
            recipient_doctor_id=req.recipient_doctor_id,
            record_ids_json=req.record_ids_json,
            permissions='view,download',
            expires_at=expires_at,
            is_revoked=False,
            created_at=now
        )
        
        req.status = 'Approved'
        db.session.add(grant)
        db.session.commit()
        
        AuditService.log_event(
            event_type='SHARING_GRANT_APPROVED',
            action=f"Patient approved record sharing",
            status='SUCCESS',
            target_resource=f"Grant: {token[:12]}...",
            details=f"Expires in {expiry_hours} hours. Recipient: {req.recipient_doctor_id}",
            user=patient_user,
            ip_address=ip_address
        )
        return grant

    @classmethod
    def reject_request(cls, request_id_val: str, patient_user: User, ip_address: str = "127.0.0.1"):
        """Patient rejects record sharing request."""
        req = SharingRequest.query.filter_by(request_id=request_id_val).first()
        if not req:
            raise ValueError("Sharing request not found.")
            
        req.status = 'Rejected'
        db.session.commit()
        
        AuditService.log_event(
            event_type='SHARING_REQUEST_REJECTED',
            action=f"Patient rejected record sharing request {request_id_val}",
            status='REJECTED',
            target_resource=f"Request: {request_id_val}",
            details=f"Declined by patient.",
            user=patient_user,
            ip_address=ip_address
        )

    @classmethod
    def revoke_grant(cls, grant_id: int, user: User, ip_address: str = "127.0.0.1"):
        """Revokes an active sharing grant with immediate effect."""
        grant = SharingGrant.query.get(grant_id)
        if not grant:
            raise ValueError("Grant not found.")
            
        grant.is_revoked = True
        grant.revoked_at = datetime.now(timezone.utc)
        if grant.request:
            grant.request.status = 'Revoked'
            
        db.session.commit()
        
        AuditService.log_event(
            event_type='SHARING_GRANT_REVOKED',
            action=f"Revoked sharing grant #{grant.id}",
            status='REVOKED',
            target_resource=f"Grant: {grant.grant_token[:12]}...",
            details=f"Token immediately invalidated.",
            user=user,
            ip_address=ip_address
        )
