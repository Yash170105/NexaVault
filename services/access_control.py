from functools import wraps
from flask import session, redirect, url_for, flash, abort, request
from models import User, Patient, Doctor, DoctorPatientAssignment, MedicalRecord, SharingGrant
from services.audit import AuditService
from services.threat_detection import ThreatDetectionService

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Session expired or authentication required. Please log in.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_active or user.is_locked:
            session.clear()
            flash('Your account has been restricted or deactivated by security policy.', 'danger')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
                
            user = User.query.get(session['user_id'])
            if not user or user.role not in allowed_roles:
                ip = request.remote_addr or '127.0.0.1'
                
                # Threat detection: Unauthorized role probe
                ThreatDetectionService.trigger_alert(
                    rule_name='UNAUTHORIZED_ROLE_PROBE',
                    severity='High',
                    details=f"User {user.email if user else 'Unknown'} with role '{user.role if user else 'None'}' "
                            f"attempted to access restricted route '{request.path}' requiring {allowed_roles}.",
                    user=user,
                    ip_address=ip
                )
                
                AuditService.log_event(
                    event_type='ACCESS_DENIED',
                    action=f"Route Access Denied: {request.path}",
                    status='DENIED',
                    target_resource=request.path,
                    details=f"Required roles: {allowed_roles}, Actual role: {user.role if user else 'None'}",
                    user=user,
                    ip_address=ip
                )
                
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class AccessControlService:
    @staticmethod
    def get_current_user():
        if 'user_id' in session:
            return User.query.get(session['user_id'])
        return None

    @classmethod
    def can_view_patient_profile(cls, user: User, patient: Patient) -> bool:
        if not user or not patient:
            return False
            
        if user.role == 'admin':
            return True
            
        if user.role == 'staff':
            return True # Demographics only
            
        if user.role == 'finance':
            return True # Billing demographics
            
        if user.role == 'patient':
            return patient.user_id == user.id
            
        if user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=user.id).first()
            if not doctor:
                return False
            # Assigned?
            assignment = DoctorPatientAssignment.query.filter_by(
                doctor_id=doctor.doctor_id, patient_id=patient.patient_id
            ).first()
            if assignment:
                return True
            # Active sharing grant?
            active_grant = SharingGrant.query.filter_by(
                recipient_doctor_id=doctor.doctor_id,
                patient_id=patient.patient_id,
                is_revoked=False
            ).first()
            if active_grant and active_grant.is_active():
                return True
            return False
            
        return False

    @classmethod
    def can_view_medical_record(cls, user: User, record: MedicalRecord) -> bool:
        """
        NexaVault Core Security Principle:
        Admin CANNOT decrypt or view clinical reports!
        Finance and Staff CANNOT view clinical reports!
        Only patient themselves or assigned/authorized doctor can decrypt!
        """
        if not user or not record:
            return False
            
        # Admin restriction: Least privilege
        if user.role == 'admin':
            return False
            
        if user.role in ['finance', 'staff']:
            return False
            
        if user.role == 'patient':
            patient = Patient.query.filter_by(user_id=user.id).first()
            return patient is not None and patient.patient_id == record.patient_id
            
        if user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=user.id).first()
            if not doctor:
                return False
                
            # 1. Primary assigned doctor?
            assignment = DoctorPatientAssignment.query.filter_by(
                doctor_id=doctor.doctor_id, patient_id=record.patient_id
            ).first()
            if assignment:
                return True
                
            # 2. Explicit active sharing grant containing this record?
            grants = SharingGrant.query.filter_by(
                recipient_doctor_id=doctor.doctor_id,
                patient_id=record.patient_id,
                is_revoked=False
            ).all()
            for grant in grants:
                if grant.is_active() and record.record_id in grant.get_record_ids():
                    return True
                    
            return False
            
        return False

    @classmethod
    def can_upload_medical_record(cls, user: User, patient_id: str) -> bool:
        if not user or user.role != 'doctor':
            return False
        doctor = Doctor.query.filter_by(user_id=user.id).first()
        if not doctor:
            return False
        assignment = DoctorPatientAssignment.query.filter_by(
            doctor_id=doctor.doctor_id, patient_id=patient_id
        ).first()
        return assignment is not None
