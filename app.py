import os
import io
import uuid
from datetime import datetime, timezone, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort, jsonify
)
from werkzeug.utils import secure_filename

from config import Config
from models import (
    db, User, Doctor, Patient, DoctorPatientAssignment,
    MedicalRecord, BillingRecord, SharingRequest, SharingGrant,
    AuditLog, SecurityAlert, SecurityIncident, RiskAssessment
)
from services.encryption import EncryptionService
from services.audit import AuditService
from services.threat_detection import ThreatDetectionService
from services.access_control import login_required, roles_required, AccessControlService
from services.sharing import SharingService
from services.integrity import IntegrityService
from services.incident_response import IncidentResponseService
from services.backup import BackupService

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Ensure required directories exist
os.makedirs(Config.INSTANCE_DIR, exist_ok=True)
os.makedirs(Config.MED_RECORDS_DIR, exist_ok=True)
os.makedirs(Config.BILLING_DIR, exist_ok=True)
os.makedirs(Config.BACKUPS_DIR, exist_ok=True)


# --------------------------------------------------------------------------
# Public & Authentication Routes
# --------------------------------------------------------------------------

@app.route('/')
def home():
    """Landing page introducing NexaVault's cybersecurity & HIPAA principles."""
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        ip = request.remote_addr or '127.0.0.1'

        user = User.query.filter_by(email=email).first()

        # Check account locking
        if user and user.is_locked:
            flash('This account is locked due to security policy violations or active investigation.', 'danger')
            AuditService.log_event(
                event_type='LOGIN_ATTEMPT_LOCKED',
                action=f"Blocked login attempt for locked account {email}",
                status='DENIED',
                target_resource=email,
                details="Account currently under isolation.",
                user=user,
                ip_address=ip
            )
            return render_template('login.html')

        # Verify password
        if user and user.check_password(password):
            # Check MFA
            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                return redirect(url_for('mfa_verify'))

            # Successful authentication
            user.failed_login_count = 0
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()

            session.clear()
            session['user_id'] = user.id
            session['email'] = user.email
            session['role'] = user.role
            session['full_name'] = user.full_name

            AuditService.log_event(
                event_type='LOGIN',
                action=f"User {user.email} authenticated successfully",
                status='SUCCESS',
                target_resource=f"Role: {user.role}",
                details=f"Session initiated from {ip}",
                user=user,
                ip_address=ip
            )

            flash(f'Welcome back, {user.full_name} ({user.role.upper()})', 'success')
            return redirect(url_for('dashboard_router'))

        else:
            # Failed authentication
            if user:
                ThreatDetectionService.check_failed_logins(user, ip)
            
            AuditService.log_event(
                event_type='LOGIN_FAILURE',
                action=f"Authentication failed for {email}",
                status='DENIED',
                target_resource=email,
                details="Invalid credentials provided.",
                ip_address=ip
            )

            flash('Invalid email or password. Security event recorded.', 'danger')

    return render_template('login.html')


@app.route('/quick-login/<role>')
def quick_login_role(role):
    """
    VIVA DEMO SHORTCUT: Instant role switching for seamless live demonstration!
    Logs directly into the requested persona.
    """
    role_email_map = {
        'admin': 'admin@test.com',
        'doctor': 'doctor@test.com',
        'patient': 'patient@test.com',
        'finance': 'finance@test.com',
        'staff': 'staff@test.com'
    }
    target_email = role_email_map.get(role.lower())
    if not target_email:
        flash('Invalid demo role requested.', 'warning')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=target_email).first()
    if not user:
        flash('Demo account not found. Please reseed database.', 'danger')
        return redirect(url_for('login'))

    user.failed_login_count = 0
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    session.clear()
    session['user_id'] = user.id
    session['email'] = user.email
    session['role'] = user.role
    session['full_name'] = user.full_name

    AuditService.log_event(
        event_type='QUICK_DEMO_LOGIN',
        action=f"Viva demo quick switch into {user.role} ({user.email})",
        status='SUCCESS',
        target_resource=f"Role: {user.role}",
        details="Demo quick-switcher activated.",
        user=user,
        ip_address=request.remote_addr or '127.0.0.1'
    )

    flash(f'⚡ Switched to Demo Persona: {user.full_name} ({user.role.upper()})', 'info')
    return redirect(url_for('dashboard_router'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Allows patient registration with assigned primary doctor."""
    doctors = Doctor.query.order_by(Doctor.doctor_id.asc()).all()
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        dob = request.form.get('dob', '1995-01-01')
        blood_group = request.form.get('blood_group', 'B+')
        gender = request.form.get('gender', 'Male')
        phone = request.form.get('phone', '+91 98250 99999')
        primary_doctor_id = request.form.get('primary_doctor_id', 'D001')

        if User.query.filter_by(email=email).first():
            flash('An account with this email address already exists.', 'warning')
            return render_template('register.html', doctors=doctors)

        # Create user account
        user = User(
            email=email,
            role='patient',
            full_name=full_name,
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        # Generate next patient ID
        p_count = Patient.query.count() + 1
        new_pid = f"P{p_count:03d}"

        # Calculate approximate age from DOB
        try:
            birth_year = int(dob.split('-')[0])
            age = max(1, 2026 - birth_year)
        except Exception:
            age = 30

        primary_doc = Doctor.query.get(primary_doctor_id)
        dept = primary_doc.department if primary_doc else 'General Medicine'

        patient = Patient(
            patient_id=new_pid,
            user_id=user.id,
            full_name=full_name,
            dob=dob,
            age=age,
            gender=gender,
            blood_group=blood_group,
            phone=phone,
            department=dept,
            status='Active',
            primary_doctor_id=primary_doctor_id
        )
        db.session.add(patient)

        # Create primary assignment
        assignment = DoctorPatientAssignment(
            doctor_id=primary_doctor_id,
            patient_id=new_pid,
            is_primary=True
        )
        db.session.add(assignment)
        db.session.commit()

        AuditService.log_event(
            event_type='PATIENT_REGISTER',
            action=f"Registered patient profile {new_pid} ({full_name})",
            status='SUCCESS',
            target_resource=new_pid,
            details=f"Assigned to Dr. {primary_doctor_id}",
            user=user,
            ip_address=request.remote_addr or '127.0.0.1'
        )

        flash('Registration complete! Please sign in with your credentials.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', doctors=doctors)


@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'mfa_user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['mfa_user_id'])
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('mfa_code', '').strip()
        # Demo code or TOTP verification
        if code == '123456' or (user.mfa_secret and pyotp.TOTP(user.mfa_secret).verify(code)):
            session.pop('mfa_user_id', None)
            session['user_id'] = user.id
            session['email'] = user.email
            session['role'] = user.role
            session['full_name'] = user.full_name

            AuditService.log_event(
                event_type='MFA_VERIFIED',
                action=f"User {user.email} passed MFA verification",
                status='SUCCESS',
                target_resource=user.email,
                user=user,
                ip_address=request.remote_addr or '127.0.0.1'
            )

            flash(f'MFA Verified. Welcome, {user.full_name}', 'success')
            return redirect(url_for('dashboard_router'))
        else:
            flash('Invalid 6-digit MFA code. (Hint: Use demo bypass code 123456)', 'danger')

    return render_template('mfa_verify.html')


@app.route('/logout')
def logout():
    user = AccessControlService.get_current_user()
    if user:
        AuditService.log_event(
            event_type='LOGOUT',
            action=f"User {user.email} logged out",
            status='SUCCESS',
            target_resource=user.email,
            user=user,
            ip_address=request.remote_addr or '127.0.0.1'
        )
    session.clear()
    flash('You have been securely signed out of NexaVault.', 'info')
    return redirect(url_for('login'))


# --------------------------------------------------------------------------
# Role-Specific Dashboards
# --------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard_router():
    """Routes the user to their specific dashboard based on backend role."""
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif role == 'patient':
        return redirect(url_for('patient_dashboard'))
    elif role == 'finance':
        return redirect(url_for('finance_dashboard'))
    elif role == 'staff':
        return redirect(url_for('staff_dashboard'))
    else:
        abort(403)


@app.route('/dashboard/admin')
@login_required
@roles_required('admin')
def admin_dashboard():
    """
    SecOps Admin Dashboard:
    - User account management
    - Real-time threat detection risk score
    - Forensic audit chain status
    - Security incidents triage
    """
    users = User.query.order_by(User.id.asc()).all()
    patient_count = Patient.query.count()
    doctor_count = Doctor.query.count()
    record_count = MedicalRecord.query.count()
    risk_data = ThreatDetectionService.calculate_system_risk_score()
    
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(10).all()
    incidents = SecurityIncident.query.order_by(SecurityIncident.created_at.desc()).limit(10).all()

    return render_template(
        'dashboards/admin.html',
        users=users,
        patient_count=patient_count,
        doctor_count=doctor_count,
        record_count=record_count,
        risk_data=risk_data,
        alerts=alerts,
        incidents=incidents
    )


@app.route('/dashboard/doctor')
@login_required
@roles_required('doctor')
def doctor_dashboard():
    """
    Doctor Clinical Dashboard:
    - Doctor profile information
    - Assigned primary patients
    - Cross-consultation records shared with this doctor
    - Encrypted medical upload form
    """
    user_id = session.get('user_id')
    doctor = Doctor.query.filter_by(user_id=user_id).first()
    if not doctor:
        flash('Doctor profile not linked. Defaulting to Dr. Aarav Sharma.', 'warning')
        doctor = Doctor.query.first()

    # Get primary assigned patients
    assignments = DoctorPatientAssignment.query.filter_by(doctor_id=doctor.doctor_id).all()
    patient_ids = [a.patient_id for a in assignments]
    # Keep Harshita P001 first
    assigned_patients = Patient.query.filter(Patient.patient_id.in_(patient_ids)).order_by(Patient.patient_id.asc()).all()

    # Get records shared with this doctor by other doctors/patients
    shared_grants = SharingGrant.query.filter_by(
        recipient_doctor_id=doctor.doctor_id,
        is_revoked=False
    ).all()
    # Filter active grants
    active_shared_grants = [g for g in shared_grants if g.is_active()]

    my_records_count = MedicalRecord.query.filter_by(uploader_id=user_id).count()

    return render_template(
        'dashboards/doctor.html',
        doctor=doctor,
        assigned_patients=assigned_patients,
        shared_grants=active_shared_grants,
        my_records_count=my_records_count
    )


@app.route('/dashboard/patient')
@login_required
@roles_required('patient')
def patient_dashboard():
    """
    Patient Vault Dashboard:
    - Harshita Makwana (P001) / Patient profile
    - Encrypted medical documents with decryption action
    - Pending doctor sharing requests with Consent Approval/Rejection buttons
    - Active sharing grants with instant Revocation button
    - Transparent access history audit trail
    """
    user_id = session.get('user_id')
    patient = Patient.query.filter_by(user_id=user_id).first()
    if not patient:
        # If logged in as demo patient, fallback to P001 Harshita Makwana
        patient = Patient.query.filter_by(patient_id='P001').first()

    records = MedicalRecord.query.filter_by(patient_id=patient.patient_id).order_by(MedicalRecord.id.desc()).all()
    billing_records = BillingRecord.query.filter_by(patient_id=patient.patient_id).all()

    # Pending consent requests
    pending_requests = SharingRequest.query.filter_by(
        patient_id=patient.patient_id,
        status='Pending_Consent'
    ).order_by(SharingRequest.id.desc()).all()

    # Active sharing grants
    grants = SharingGrant.query.filter_by(
        patient_id=patient.patient_id,
        is_revoked=False
    ).all()
    active_grants = [g for g in grants if g.is_active()]

    # Transparent access history (audit logs concerning this patient's records)
    my_audit_history = AuditLog.query.filter(
        (AuditLog.target_resource.like(f"%{patient.patient_id}%")) | 
        (AuditLog.target_resource.like("%MR-1001%")) |
        (AuditLog.target_resource.like("%MR-1002%"))
    ).order_by(AuditLog.id.desc()).limit(15).all()

    return render_template(
        'dashboards/patient.html',
        patient=patient,
        records=records,
        billing_records=billing_records,
        pending_requests=pending_requests,
        active_grants=active_grants,
        my_audit_history=my_audit_history
    )


@app.route('/dashboard/finance')
@login_required
@roles_required('finance', 'admin')
def finance_dashboard():
    """
    Finance Dashboard:
    - Billing statements and invoices
    - Strict backend denial demonstration if attempting to access medical reports!
    """
    bills = BillingRecord.query.order_by(BillingRecord.id.desc()).all()
    # List of patients for issuing new bills
    patients = Patient.query.order_by(Patient.patient_id.asc()).all()

    return render_template('dashboards/finance.html', bills=bills, patients=patients)


@app.route('/dashboard/staff')
@login_required
@roles_required('staff', 'admin')
def staff_dashboard():
    """Staff Dashboard: Read-only patient demographics, no clinical or billing data."""
    patients = Patient.query.order_by(Patient.patient_id.asc()).all()
    return render_template('dashboards/staff.html', patients=patients)


# --------------------------------------------------------------------------
# Shared Directories & Profile Routes
# --------------------------------------------------------------------------

@app.route('/doctors')
def list_doctors():
    """Directory of all 10 Indian doctors."""
    doctors = Doctor.query.order_by(Doctor.doctor_id.asc()).all()
    return render_template('doctors.html', doctors=doctors)


@app.route('/doctors/<doctor_id>')
def doctor_profile_detail(doctor_id):
    """Detailed profile of an individual doctor and assigned patients."""
    doctor = Doctor.query.get_or_404(doctor_id)
    assignments = DoctorPatientAssignment.query.filter_by(doctor_id=doctor_id).all()
    patient_ids = [a.patient_id for a in assignments]
    assigned_patients = Patient.query.filter(Patient.patient_id.in_(patient_ids)).order_by(Patient.patient_id.asc()).all()
    return render_template('doctor_detail.html', doctor=doctor, assigned_patients=assigned_patients)


@app.route('/patients')
@login_required
def list_patients():
    """
    Authorized Patient Directory (15 Patients).
    Harshita Makwana (P001) is guaranteed to appear first!
    """
    patients = Patient.query.order_by(Patient.patient_id.asc()).all()
    return render_template('patients.html', patients=patients)


@app.route('/patient/<patient_id>/files')
@login_required
def patient_files_view(patient_id):
    """
    Authorized Medical Records Vault.
    Strictly enforces zero-trust access control:
    - Admins CANNOT decrypt or view medical files directly!
    - Finance & Staff CANNOT view medical files!
    - Doctors MUST be assigned or hold an active sharing grant!
    - Patients can view only their own records!
    """
    patient = Patient.query.get_or_404(patient_id)
    user = AccessControlService.get_current_user()

    # Check permission
    can_access = AccessControlService.can_view_patient_profile(user, patient)
    
    # If Admin, explicitly inform of least-privilege principle
    if user.role == 'admin':
        AuditService.log_event(
            event_type='ACCESS_DENIED_LEAST_PRIVILEGE',
            action=f"Admin tried to access clinical records for {patient_id}",
            status='DENIED',
            target_resource=f"Clinical Files {patient_id}",
            details="Admin account management role explicitly excludes clinical report decryption.",
            user=user,
            ip_address=request.remote_addr or '127.0.0.1'
        )
        flash('Least-Privilege Enforcement: Admin role cannot view or decrypt clinical medical files directly.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if not can_access:
        ThreatDetectionService.check_unauthorized_access(
            user=user,
            target_resource=f"Patient Files: {patient_id}",
            ip_address=request.remote_addr or '127.0.0.1',
            reason="User is not the primary doctor and lacks an active sharing grant."
        )
        AuditService.log_event(
            event_type='ACCESS_DENIED',
            action=f"Unauthorized attempt to access clinical records of {patient_id}",
            status='DENIED',
            target_resource=f"Patient Files {patient_id}",
            details="RBAC assignment and grant check failed.",
            user=user,
            ip_address=request.remote_addr or '127.0.0.1'
        )
        flash('Access Denied: You are not authorized to view this patient’s clinical records. Security event recorded.', 'danger')
        return redirect(url_for('dashboard_router'))

    records = MedicalRecord.query.filter_by(patient_id=patient_id).order_by(MedicalRecord.id.desc()).all()
    return render_template('patient_files.html', patient=patient, records=records)


# --------------------------------------------------------------------------
# Cryptographic Medical File Operations
# --------------------------------------------------------------------------

@app.route('/records/upload', methods=['POST'])
@login_required
@roles_required('doctor')
def upload_medical_record():
    """
    Encrypts and uploads medical report using AES-256-GCM envelope encryption.
    """
    user = AccessControlService.get_current_user()
    patient_id = request.form.get('patient_id')
    title = request.form.get('title', '').strip()
    category = request.form.get('category', 'Lab Report')
    description = request.form.get('description', '')
    ip = request.remote_addr or '127.0.0.1'

    # Check authorization to upload for this patient
    if not AccessControlService.can_upload_medical_record(user, patient_id):
        ThreatDetectionService.check_unauthorized_access(user, f"Upload target {patient_id}", ip, "Not assigned doctor")
        flash('Access Denied: You can only upload records for assigned patients.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    uploaded_file = request.files.get('file')
    if not uploaded_file or uploaded_file.filename == '':
        flash('Please select a valid medical document file.', 'warning')
        return redirect(url_for('doctor_dashboard'))

    original_filename = secure_filename(uploaded_file.filename)
    plaintext_bytes = uploaded_file.read()

    if len(plaintext_bytes) == 0:
        flash('File cannot be empty.', 'warning')
        return redirect(url_for('doctor_dashboard'))

    # Step 1-4: Envelope Encryption with AES-256-GCM
    enc_service = EncryptionService()
    enc_result = enc_service.encrypt_file_data(plaintext_bytes)

    # Generate record ID
    rec_count = MedicalRecord.query.count() + 1
    new_rec_id = f"MR-{1000 + rec_count}"

    # Step 5: Save ciphertext blob to disk
    disk_filename = f"{new_rec_id}_{uuid.uuid4().hex[:8]}.enc"
    disk_filepath = os.path.join(Config.MED_RECORDS_DIR, disk_filename)

    with open(disk_filepath, 'wb') as f:
        f.write(enc_result['ciphertext'])

    # Save metadata & wrapped DEK to SQLite
    rec_obj = MedicalRecord(
        record_id=new_rec_id,
        patient_id=patient_id,
        uploader_id=user.id,
        title=title,
        category=category,
        original_filename=original_filename,
        encrypted_filepath=disk_filepath,
        wrapped_dek=enc_result['wrapped_dek_b64'],
        dek_nonce=enc_result['dek_nonce_b64'],
        dek_tag=enc_result['dek_tag_b64'],
        file_nonce=enc_result['file_nonce_b64'],
        file_tag=enc_result['file_tag_b64'],
        sha256_hash=enc_result['sha256_hash'],
        file_size=len(plaintext_bytes),
        mime_type=uploaded_file.mimetype or 'application/pdf',
        description=description
    )
    db.session.add(rec_obj)
    db.session.commit()

    AuditService.log_event(
        event_type='FILE_UPLOAD_ENCRYPTED',
        action=f"Uploaded and encrypted {new_rec_id} for {patient_id}",
        status='SUCCESS',
        target_resource=new_rec_id,
        details=f"AES-256-GCM envelope encrypted. SHA256: {enc_result['sha256_hash'][:16]}...",
        user=user,
        ip_address=ip
    )

    flash(f'✓ Medical record [{new_rec_id}] encrypted with AES-256-GCM and saved to vault.', 'success')
    return redirect(url_for('patient_files_view', patient_id=patient_id))


@app.route('/records/<record_id>/download')
@login_required
def download_medical_record(record_id):
    """
    Decrypts and serves a medical file:
    1. Verifies caller RBAC and assignment / sharing grant.
    2. Unwraps DEK using Master KEK.
    3. Decrypts ciphertext with AES-256-GCM verifying auth tag.
    4. Computes SHA-256 of decrypted bytes and compares with trusted database hash.
    5. If mismatch -> triggers Critical alert, aborts download!
    6. Streams decrypted content directly from memory.
    """
    user = AccessControlService.get_current_user()
    record = MedicalRecord.query.filter_by(record_id=record_id).first_or_404()
    ip = request.remote_addr or '127.0.0.1'

    # Check 1: Authorization
    can_view = AccessControlService.can_view_medical_record(user, record)
    if not can_view:
        ThreatDetectionService.check_unauthorized_access(
            user=user,
            target_resource=f"MedicalRecord: {record.record_id}",
            ip_address=ip,
            reason=f"Role '{user.role}' lacks decryption grant for patient '{record.patient_id}'."
        )
        AuditService.log_event(
            event_type='RECORD_DECRYPTION_DENIED',
            action=f"Unauthorized decryption attempt on {record.record_id}",
            status='DENIED',
            target_resource=record.record_id,
            details=f"User {user.email} denied access.",
            user=user,
            ip_address=ip
        )
        abort(403)

    # Check bulk download velocity
    ThreatDetectionService.check_bulk_downloads(user, ip)

    # Check 2: Physical existence
    if not os.path.exists(record.encrypted_filepath):
        ThreatDetectionService.check_integrity_failure(record.record_id, record.original_filename, "Physical file missing", user, ip)
        flash('Critical Error: Encrypted file missing from vault storage.', 'danger')
        abort(404)

    # Check 3-4: Decrypt & Verify Integrity
    try:
        with open(record.encrypted_filepath, 'rb') as f:
            ciphertext = f.read()

        enc_service = EncryptionService()
        decrypted_bytes = enc_service.decrypt_file_data(
            ciphertext=ciphertext,
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
            dek_tag_b64=record.dek_tag,
            file_nonce_b64=record.file_nonce,
            file_tag_b64=record.file_tag,
            expected_sha256=record.sha256_hash
        )

        AuditService.log_event(
            event_type='FILE_DECRYPT_SERVED',
            action=f"Decrypted and served record {record.record_id}",
            status='SUCCESS',
            target_resource=record.record_id,
            details=f"GCM Tag verified. SHA-256 hash matched trusted baseline.",
            user=user,
            ip_address=ip
        )

        # Stream decrypted file
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=record.mime_type or 'application/pdf',
            as_attachment=True,
            download_name=record.original_filename
        )

    except ValueError as e:
        # Cryptographic tag mismatch or hash alteration detected!
        ThreatDetectionService.check_integrity_failure(
            record_id=record.record_id,
            filename=record.original_filename,
            details=str(e),
            user=user,
            ip_address=ip
        )
        AuditService.log_event(
            event_type='FILE_TAMPER_DETECTED',
            action=f"Decryption integrity violation on {record.record_id}",
            status='TAMPER_DETECTED',
            target_resource=record.record_id,
            details=str(e),
            user=user,
            ip_address=ip
        )
        flash(f'CRITICAL SECURITY ALERT: Cryptographic integrity violation detected for {record.record_id}. Decryption blocked to prevent data compromise.', 'danger')
        return redirect(url_for('patient_files_view', patient_id=record.patient_id))


@app.route('/records/<record_id>/verify')
@login_required
def verify_record_integrity_route(record_id):
    """Verifies AES-GCM tag and SHA-256 hash without downloading."""
    user = AccessControlService.get_current_user()
    record = MedicalRecord.query.filter_by(record_id=record_id).first_or_404()
    ip = request.remote_addr or '127.0.0.1'

    result = IntegrityService.verify_record_integrity(record, user, ip)
    if result['is_valid']:
        flash(f"✓ Cryptographic Verification Passed: {record.record_id} SHA-256 matches trusted baseline ({result['sha256'][:16]}...).", 'success')
    else:
        flash(f"⚠️ INTEGRITY FAILURE DETECTED: {result['message']}", 'danger')

    return redirect(url_for('patient_files_view', patient_id=record.patient_id))


# --------------------------------------------------------------------------
# Controlled Sharing & Patient Consent Routes
# --------------------------------------------------------------------------

@app.route('/sharing')
@login_required
def sharing_hub():
    """Portal for creating, approving, rejecting, and revoking sharing grants."""
    user = AccessControlService.get_current_user()
    doctors = Doctor.query.order_by(Doctor.doctor_id.asc()).all()
    patients = Patient.query.order_by(Patient.patient_id.asc()).all()

    if user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user.id).first() or Patient.query.filter_by(patient_id='P001').first()
        requests = SharingRequest.query.filter_by(patient_id=patient.patient_id).order_by(SharingRequest.id.desc()).all()
        grants = SharingGrant.query.filter_by(patient_id=patient.patient_id).order_by(SharingGrant.id.desc()).all()
    elif user.role == 'doctor':
        doc = Doctor.query.filter_by(user_id=user.id).first()
        requests = SharingRequest.query.filter(
            (SharingRequest.requesting_doctor_id == (doc.doctor_id if doc else 'D001')) |
            (SharingRequest.recipient_doctor_id == (doc.doctor_id if doc else 'D001'))
        ).order_by(SharingRequest.id.desc()).all()
        grants = SharingGrant.query.filter(
            (SharingGrant.grantor_doctor_id == (doc.doctor_id if doc else 'D001')) |
            (SharingGrant.recipient_doctor_id == (doc.doctor_id if doc else 'D001'))
        ).order_by(SharingGrant.id.desc()).all()
    else:
        # Admin or others see full directory
        requests = SharingRequest.query.order_by(SharingRequest.id.desc()).limit(20).all()
        grants = SharingGrant.query.order_by(SharingGrant.id.desc()).limit(20).all()

    return render_template('sharing.html', requests=requests, grants=grants, doctors=doctors, patients=patients)


@app.route('/sharing/create', methods=['POST'])
@login_required
@roles_required('doctor')
def create_sharing_request_route():
    user = AccessControlService.get_current_user()
    doctor = Doctor.query.filter_by(user_id=user.id).first()
    if not doctor:
        doctor = Doctor.query.first()

    patient_id = request.form.get('patient_id')
    recipient_doctor_id = request.form.get('recipient_doctor_id')
    record_ids_raw = request.form.get('record_ids', 'MR-1001')
    reason = request.form.get('reason', 'Specialist consultation')

    record_ids = [r.strip() for r in record_ids_raw.split(',') if r.strip()]

    SharingService.create_request(
        requesting_doctor=doctor,
        patient_id=patient_id,
        recipient_doctor_id=recipient_doctor_id,
        record_ids=record_ids,
        reason=reason,
        user=user,
        ip_address=request.remote_addr or '127.0.0.1'
    )

    flash('Sharing request created and submitted for patient consent authorization.', 'info')
    return redirect(url_for('sharing_hub'))


@app.route('/sharing/request/<req_id>/approve', methods=['POST'])
@login_required
def approve_sharing_request(req_id):
    user = AccessControlService.get_current_user()
    expiry_hours = int(request.form.get('expiry_hours', 48))
    
    try:
        grant = SharingService.approve_request(
            request_id_val=req_id,
            patient_user=user,
            expiry_hours=expiry_hours,
            ip_address=request.remote_addr or '127.0.0.1'
        )
        flash(f'✓ Sharing grant approved! Token generated: {grant.grant_token[:16]}... Valid for {expiry_hours} hours.', 'success')
    except Exception as e:
        flash(f'Error approving request: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('sharing_hub'))


@app.route('/sharing/request/<req_id>/reject', methods=['POST'])
@login_required
def reject_sharing_request(req_id):
    user = AccessControlService.get_current_user()
    try:
        SharingService.reject_request(req_id, user, request.remote_addr or '127.0.0.1')
        flash('Sharing request rejected. Doctor will not have access to specified files.', 'info')
    except Exception as e:
        flash(f'Error rejecting request: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('sharing_hub'))


@app.route('/sharing/grant/<int:grant_id>/revoke', methods=['POST'])
@login_required
def revoke_sharing_grant_route(grant_id):
    user = AccessControlService.get_current_user()
    try:
        SharingService.revoke_grant(grant_id, user, request.remote_addr or '127.0.0.1')
        flash('✓ Sharing grant revoked immediately. Any further decryption attempts using this token will be denied.', 'warning')
    except Exception as e:
        flash(f'Error revoking grant: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('sharing_hub'))


@app.route('/access-shared', methods=['GET', 'POST'])
def access_shared_page():
    """Redeems a valid high-entropy sharing token."""
    grant = None
    shared_records = []
    token = request.args.get('token') or request.form.get('token')

    if token:
        grant = SharingGrant.query.filter_by(grant_token=token).first()
        if not grant:
            flash('Invalid sharing token. Record not found.', 'danger')
        elif not grant.is_active():
            flash('This sharing token has expired or has been revoked by the patient.', 'danger')
            grant = None
        else:
            record_ids = grant.get_record_ids()
            shared_records = MedicalRecord.query.filter(MedicalRecord.record_id.in_(record_ids)).all()

            AuditService.log_event(
                event_type='SHARING_TOKEN_REDEEMED',
                action=f"Token redeemed for Patient {grant.patient_id}",
                status='SUCCESS',
                target_resource=grant.grant_token[:12],
                details=f"Authorized {len(shared_records)} files.",
                ip_address=request.remote_addr or '127.0.0.1'
            )

    return render_template('access_shared.html', grant=grant, shared_records=shared_records, token=token)


# --------------------------------------------------------------------------
# Threat Detection, Incidents & Audit Pages
# --------------------------------------------------------------------------

@app.route('/security')
@login_required
@roles_required('admin', 'doctor')
def security_dashboard():
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).all()
    risk_data = ThreatDetectionService.calculate_system_risk_score()
    return render_template('security.html', alerts=alerts, risk_data=risk_data)


@app.route('/incidents')
@login_required
@roles_required('admin', 'doctor')
def incidents_list():
    incidents = SecurityIncident.query.order_by(SecurityIncident.created_at.desc()).all()
    return render_template('incidents.html', incidents=incidents)


@app.route('/incidents/<int:incident_id>/update', methods=['POST'])
@login_required
@roles_required('admin')
def update_incident_route(incident_id):
    user = AccessControlService.get_current_user()
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    IncidentResponseService.update_incident_status(incident_id, new_status, notes, user)
    flash(f'Incident #{incident_id} updated to {new_status}.', 'success')
    return redirect(url_for('incidents_list'))


@app.route('/admin/users/<int:user_id>/lock', methods=['POST'])
@login_required
@roles_required('admin')
def lock_user(user_id):
    admin = AccessControlService.get_current_user()
    IncidentResponseService.isolate_user_account(user_id, admin)
    flash(f'User #{user_id} account locked and isolated.', 'warning')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<int:user_id>/unlock', methods=['POST'])
@login_required
@roles_required('admin')
def unlock_user(user_id):
    admin = AccessControlService.get_current_user()
    IncidentResponseService.unlock_user_account(user_id, admin)
    flash(f'User #{user_id} unlocked and access restored.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/audit-logs')
@login_required
@roles_required('admin')
def audit_logs_view():
    search = request.args.get('search', '').strip()
    event_type = request.args.get('event_type', '').strip()

    query = AuditLog.query
    if search:
        query = query.filter(
            (AuditLog.user_email.ilike(f'%{search}%')) |
            (AuditLog.action.ilike(f'%{search}%')) |
            (AuditLog.target_resource.ilike(f'%{search}%'))
        )
    if event_type:
        query = query.filter_by(event_type=event_type)

    logs = query.order_by(AuditLog.id.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs, search_query=search, event_type_filter=event_type)


@app.route('/risk-assessment')
def risk_assessment_view():
    controls = RiskAssessment.query.order_by(RiskAssessment.id.asc()).all()
    return render_template('risk_assessment.html', controls=controls)


@app.route('/backup')
@login_required
@roles_required('admin')
def list_backups_view():
    backups = BackupService.list_backups()
    return render_template('backup.html', backups=backups)


@app.route('/backup/create')
@login_required
@roles_required('admin')
def create_contingency_backup():
    admin = AccessControlService.get_current_user()
    res = BackupService.create_encrypted_backup(admin)
    flash(f"✓ Backup snapshot created successfully: {res['filename']} ({res['size']} bytes). SHA256 recorded.", 'success')
    return redirect(url_for('list_backups_view'))


@app.route('/billing/create', methods=['POST'])
@login_required
@roles_required('finance', 'admin')
def create_billing_record_route():
    user = AccessControlService.get_current_user()
    patient_id = request.form.get('patient_id')
    title = request.form.get('title')
    amount = float(request.form.get('amount', 0))

    b_count = BillingRecord.query.count() + 1
    inv_id = f"INV-2026-{b_count:03d}"

    bill = BillingRecord(
        invoice_id=inv_id,
        patient_id=patient_id,
        uploader_id=user.id,
        title=title,
        amount=amount,
        status='Pending'
    )
    db.session.add(bill)
    db.session.commit()

    AuditService.log_event(
        event_type='INVOICE_CREATED',
        action=f"Created invoice {inv_id} for Patient {patient_id}",
        status='SUCCESS',
        target_resource=inv_id,
        details=f"Amount: ₹{amount:.2f}",
        user=user,
        ip_address=request.remote_addr or '127.0.0.1'
    )

    flash(f'Invoice {inv_id} generated for Patient {patient_id}.', 'success')
    return redirect(url_for('finance_dashboard'))


# --------------------------------------------------------------------------
# Forensic API Endpoints & Viva Demonstration Simulators
# --------------------------------------------------------------------------

@app.route('/api/audit/verify')
@login_required
@roles_required('admin')
def api_verify_audit_chain():
    """Returns cryptographic verification of the sequential SHA-256 audit chain."""
    result = AuditService.verify_audit_chain()
    if not result['is_valid']:
        ThreatDetectionService.trigger_alert(
            rule_name='AUDIT_LOG_TAMPERING',
            severity='Critical',
            details=f"Forensic verification failed: {result['message']}",
            user=AccessControlService.get_current_user(),
            ip_address=request.remote_addr or '127.0.0.1'
        )
    return jsonify(result)


@app.route('/api/tamper-demo', methods=['POST'])
@login_required
@roles_required('admin')
def api_tamper_demo():
    """
    FOR VIVA DEFENSE DEMO:
    Simulates attacks on demand so examiners can watch real-time detection:
    - 'file': Flips a byte in an encrypted record on disk.
    - 'audit': Mutates an audit log entry in SQLite without recalculating the hash chain.
    - 'bruteforce': Generates 3 failed logins for an account.
    """
    data = request.get_json() or {}
    tamper_type = data.get('type')
    target_id = data.get('target_id')
    ip = request.remote_addr or '127.0.0.1'

    if tamper_type == 'file':
        IntegrityService.simulate_tampering_attack('MR-1001')
        return jsonify({
            'status': 'tampered',
            'message': 'Simulated bit-flip attack on MR-1001 on physical disk! Now attempt to decrypt or verify it to see AES-GCM tag rejection in action.'
        })

    elif tamper_type == 'audit':
        # Modify the details of log #1 directly in database to break the hash chain
        log = AuditLog.query.order_by(AuditLog.id.asc()).first()
        if log:
            log.details = log.details + " [MALICIOUS_UNAUTHORIZED_MUTATION]"
            db.session.commit()
            return jsonify({
                'status': 'tampered',
                'message': f'Tampered with Audit Entry #{log.id}! Click "Verify Cryptographic Chain" to watch the forensic chain breaker detect it.'
            })

    elif tamper_type == 'bruteforce':
        target_user = User.query.filter_by(email='admin@test.com').first()
        if target_user:
            for _ in range(3):
                ThreatDetectionService.check_failed_logins(target_user, ip)
            return jsonify({
                'status': 'alert_generated',
                'message': 'Simulated repeated failed logins! Medium severity alert and risk score increased.'
            })

    return jsonify({'status': 'unknown_type', 'message': 'Unknown simulation type.'}), 400


@app.route('/admin/reseed')
@login_required
@roles_required('admin')
def reseed_database_route():
    """Reseeds the database to pristine baseline for demonstration restart."""
    from seed_data import seed_database
    seed_database()
    flash('Database reseeded cleanly to the 15-patient, 10-doctor baseline!', 'success')
    return redirect(url_for('admin_dashboard'))


# --------------------------------------------------------------------------
# Main Execution Entrypoint
# --------------------------------------------------------------------------

if __name__ == '__main__':
    # Local development server
    app.run(host='127.0.0.1', port=5000, debug=True)
