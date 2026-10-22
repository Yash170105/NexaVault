from datetime import datetime, timezone
from models import db, SecurityIncident, User
from services.audit import AuditService

class IncidentResponseService:
    @classmethod
    def update_incident_status(cls, incident_id: int, new_status: str, notes: str, user: User):
        """
        Updates investigation status (Open, Investigating, Resolved, False_Positive)
        and logs remediation action.
        """
        incident = SecurityIncident.query.get(incident_id)
        if not incident:
            raise ValueError("Incident not found.")
            
        old_status = incident.status
        incident.status = new_status
        if notes:
            incident.notes = (incident.notes or '') + f"\n[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}] {user.full_name}: {notes}"
        
        incident.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        AuditService.log_event(
            event_type='INCIDENT_TRIAGE',
            action=f"Incident {incident.incident_number} status updated to {new_status}",
            status='SUCCESS',
            target_resource=incident.incident_number,
            details=f"Status transitioned from {old_status} to {new_status}. Notes: {notes}",
            user=user
        )
        return incident

    @classmethod
    def isolate_user_account(cls, target_user_id: int, admin_user: User):
        """Locks an account subject to security investigation."""
        target_user = User.query.get(target_user_id)
        if not target_user:
            raise ValueError("User not found.")
            
        target_user.is_locked = True
        db.session.commit()
        
        AuditService.log_event(
            event_type='ACCOUNT_ISOLATION',
            action=f"Security lockdown executed on user {target_user.email}",
            status='WARNING',
            target_resource=f"User #{target_user.id}",
            details=f"Account locked by Admin {admin_user.email} under incident remediation protocol.",
            user=admin_user
        )
        return target_user

    @classmethod
    def unlock_user_account(cls, target_user_id: int, admin_user: User):
        """Restores account access after triage and clearance."""
        target_user = User.query.get(target_user_id)
        if not target_user:
            raise ValueError("User not found.")
            
        target_user.is_locked = False
        target_user.failed_login_count = 0
        db.session.commit()
        
        AuditService.log_event(
            event_type='ACCOUNT_UNLOCKED',
            action=f"Security clearance restored for user {target_user.email}",
            status='SUCCESS',
            target_resource=f"User #{target_user.id}",
            details=f"Account unlocked by Admin {admin_user.email}.",
            user=admin_user
        )
        return target_user
