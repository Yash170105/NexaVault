import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(30), nullable=False)  # admin, doctor, patient, finance, staff
    full_name = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_locked = db.Column(db.Boolean, default=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    doctor_profile = db.relationship('Doctor', backref='user_account', uselist=False, cascade='all, delete-orphan')
    patient_profile = db.relationship('Patient', backref='user_account', uselist=False, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'is_locked': self.is_locked,
            'mfa_enabled': self.mfa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class Doctor(db.Model):
    __tablename__ = 'doctors'
    
    doctor_id = db.Column(db.String(20), primary_key=True)  # D001 - D010
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    full_name = db.Column(db.String(120), nullable=False)
    specialization = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    qualification = db.Column(db.String(120), nullable=False)
    experience_years = db.Column(db.Integer, nullable=False)
    bio = db.Column(db.Text, nullable=False)
    contact_email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    avatar_initials = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    assignments = db.relationship('DoctorPatientAssignment', backref='doctor', lazy='dynamic')

    def to_dict(self):
        return {
            'doctor_id': self.doctor_id,
            'full_name': self.full_name,
            'specialization': self.specialization,
            'department': self.department,
            'qualification': self.qualification,
            'experience_years': self.experience_years,
            'bio': self.bio,
            'contact_email': self.contact_email,
            'phone': self.phone,
            'avatar_initials': self.avatar_initials,
            'assigned_count': self.assignments.count()
        }


class Patient(db.Model):
    __tablename__ = 'patients'
    
    patient_id = db.Column(db.String(20), primary_key=True)  # P001 - P015
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    full_name = db.Column(db.String(120), nullable=False)
    dob = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    blood_group = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(50), default='Active')
    primary_doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    primary_doctor = db.relationship('Doctor', foreign_keys=[primary_doctor_id], backref='primary_patients')
    assignments = db.relationship('DoctorPatientAssignment', backref='patient', lazy='dynamic')
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy='dynamic', cascade='all, delete-orphan')
    billing_records = db.relationship('BillingRecord', backref='patient', lazy='dynamic', cascade='all, delete-orphan')
    sharing_requests = db.relationship('SharingRequest', backref='patient', lazy='dynamic')
    sharing_grants = db.relationship('SharingGrant', backref='patient', lazy='dynamic')

    def to_dict(self):
        return {
            'patient_id': self.patient_id,
            'full_name': self.full_name,
            'dob': self.dob,
            'age': self.age,
            'gender': self.gender,
            'blood_group': self.blood_group,
            'phone': self.phone,
            'department': self.department,
            'status': self.status,
            'primary_doctor_id': self.primary_doctor_id,
            'primary_doctor_name': self.primary_doctor.full_name if self.primary_doctor else 'Unassigned'
        }


class DoctorPatientAssignment(db.Model):
    __tablename__ = 'doctor_patient_assignments'
    
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=False)
    patient_id = db.Column(db.String(20), db.ForeignKey('patients.patient_id'), nullable=False)
    is_primary = db.Column(db.Boolean, default=True)
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'
    
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(30), unique=True, nullable=False, index=True)
    patient_id = db.Column(db.String(20), db.ForeignKey('patients.patient_id'), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploader = db.relationship('User', foreign_keys=[uploader_id], backref='uploaded_records')
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(60), nullable=False)  # Lab Report, MRI Scan, Prescription, Clinical Summary, etc.
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filepath = db.Column(db.String(500), nullable=False)
    
    # AES-256-GCM & Key Wrapping
    wrapped_dek = db.Column(db.Text, nullable=False)  # Encrypted Data Encryption Key (base64)
    dek_nonce = db.Column(db.String(64), nullable=False)  # Nonce used for DEK wrapping (base64)
    dek_tag = db.Column(db.String(64), nullable=False)    # GCM auth tag for DEK (base64)
    file_nonce = db.Column(db.String(64), nullable=False) # Nonce used for encrypting file payload (base64)
    file_tag = db.Column(db.String(64), nullable=False)   # GCM auth tag for file payload (base64)
    sha256_hash = db.Column(db.String(64), nullable=False) # Trusted SHA-256 of original plaintext
    
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), default='application/pdf')
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'record_id': self.record_id,
            'patient_id': self.patient_id,
            'title': self.title,
            'category': self.category,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'sha256_hash': self.sha256_hash,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M UTC')
        }


class BillingRecord(db.Model):
    __tablename__ = 'billing_records'
    
    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.String(30), unique=True, nullable=False, index=True)
    patient_id = db.Column(db.String(20), db.ForeignKey('patients.patient_id'), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), default='Pending')  # Paid, Pending, Overdue
    original_filename = db.Column(db.String(255), nullable=True)
    encrypted_filepath = db.Column(db.String(500), nullable=True)
    
    # AES-256-GCM metadata
    wrapped_dek = db.Column(db.Text, nullable=True)
    dek_nonce = db.Column(db.String(64), nullable=True)
    dek_tag = db.Column(db.String(64), nullable=True)
    file_nonce = db.Column(db.String(64), nullable=True)
    file_tag = db.Column(db.String(64), nullable=True)
    sha256_hash = db.Column(db.String(64), nullable=True)
    
    file_size = db.Column(db.Integer, default=0)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'invoice_id': self.invoice_id,
            'patient_id': self.patient_id,
            'patient_name': self.patient.full_name if self.patient else 'Unknown',
            'title': self.title,
            'amount': self.amount,
            'status': self.status,
            'original_filename': self.original_filename,
            'has_file': bool(self.encrypted_filepath),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M UTC')
        }


class SharingRequest(db.Model):
    __tablename__ = 'sharing_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    patient_id = db.Column(db.String(20), db.ForeignKey('patients.patient_id'), nullable=False)
    requesting_doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=False)
    recipient_doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=False)
    record_ids_json = db.Column(db.Text, nullable=False)  # JSON array of record_ids e.g. ["MR-1001", "MR-1002"]
    status = db.Column(db.String(30), default='Pending_Consent')  # Pending_Consent, Approved, Rejected, Revoked
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    requesting_doctor = db.relationship('Doctor', foreign_keys=[requesting_doctor_id])
    recipient_doctor = db.relationship('Doctor', foreign_keys=[recipient_doctor_id])

    def get_record_ids(self):
        try:
            return json.loads(self.record_ids_json)
        except Exception:
            return []

    def set_record_ids(self, records_list):
        self.record_ids_json = json.dumps(records_list)


class SharingGrant(db.Model):
    __tablename__ = 'sharing_grants'
    
    id = db.Column(db.Integer, primary_key=True)
    grant_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    sharing_request_id = db.Column(db.Integer, db.ForeignKey('sharing_requests.id'), nullable=True)
    patient_id = db.Column(db.String(20), db.ForeignKey('patients.patient_id'), nullable=False)
    grantor_doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=False)
    recipient_doctor_id = db.Column(db.String(20), db.ForeignKey('doctors.doctor_id'), nullable=False)
    record_ids_json = db.Column(db.Text, nullable=False)  # JSON list of allowed record IDs
    permissions = db.Column(db.String(50), default='view,download')
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    grantor = db.relationship('Doctor', foreign_keys=[grantor_doctor_id])
    recipient = db.relationship('Doctor', foreign_keys=[recipient_doctor_id])
    request = db.relationship('SharingRequest', backref='grant', uselist=False)

    def is_active(self):
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return (not self.is_revoked) and (now <= expires)

    def get_record_ids(self):
        try:
            return json.loads(self.record_ids_json)
        except Exception:
            return []


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    event_type = db.Column(db.String(60), nullable=False, index=True)  # LOGIN, LOGOUT, FILE_UPLOAD, FILE_DECRYPT, ACCESS_DENIED, etc.
    user_id = db.Column(db.Integer, nullable=True)
    user_email = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(30), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    target_resource = db.Column(db.String(150), nullable=True)
    status = db.Column(db.String(30), default='SUCCESS')  # SUCCESS, DENIED, TAMPER_DETECTED, ERROR
    details = db.Column(db.Text, nullable=True)
    
    # Tamper-Evident Hash Chain
    previous_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'event_type': self.event_type,
            'user_email': self.user_email or 'Anonymous',
            'role': self.role or 'N/A',
            'ip_address': self.ip_address or '127.0.0.1',
            'action': self.action,
            'target_resource': self.target_resource or '-',
            'status': self.status,
            'details': self.details,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash
        }


class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    rule_name = db.Column(db.String(100), nullable=False)  # REPEATED_FAILED_LOGIN, UNAUTHORIZED_ACCESS, etc.
    severity = db.Column(db.String(20), nullable=False)     # Low, Medium, High, Critical
    risk_score_impact = db.Column(db.Integer, default=10)
    source_ip = db.Column(db.String(45), nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    user_email = db.Column(db.String(120), nullable=True)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), default='Open')       # Open, Investigating, Resolved, False_Positive

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'rule_name': self.rule_name,
            'severity': self.severity,
            'risk_score_impact': self.risk_score_impact,
            'source_ip': self.source_ip,
            'user_email': self.user_email or 'Unknown',
            'details': self.details,
            'status': self.status
        }


class SecurityIncident(db.Model):
    __tablename__ = 'security_incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_number = db.Column(db.String(30), unique=True, nullable=False)  # INC-2026-001
    alert_id = db.Column(db.Integer, db.ForeignKey('security_alerts.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(30), default='Open')  # Open, Investigating, Resolved, False_Positive
    assigned_to = db.Column(db.String(100), default='SecOps Lead')
    actions_taken = db.Column(db.Text, default='Initial triage started.')
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    alert = db.relationship('SecurityAlert', backref='incidents')

    def to_dict(self):
        return {
            'id': self.id,
            'incident_number': self.incident_number,
            'alert_id': self.alert_id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'actions_taken': self.actions_taken,
            'notes': self.notes,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M UTC'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M UTC')
        }


class RiskAssessment(db.Model):
    __tablename__ = 'risk_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.String(30), unique=True, nullable=False)  # AC-1, AU-2, etc.
    category = db.Column(db.String(80), nullable=False)
    control_name = db.Column(db.String(200), nullable=False)
    safeguard_type = db.Column(db.String(40), nullable=False)  # Technical, Administrative, Physical
    hipaa_citation = db.Column(db.String(80), nullable=False) # e.g. 45 CFR § 164.312(a)(1)
    status = db.Column(db.String(30), default='Implemented')  # Implemented, In_Review, Requires_Action
    notes = db.Column(db.Text, nullable=True)
    last_reviewed = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
