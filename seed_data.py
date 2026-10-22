import os
import uuid
from datetime import datetime, timezone, timedelta
from flask import Flask
from config import Config
from models import (
    db, User, Doctor, Patient, DoctorPatientAssignment,
    MedicalRecord, BillingRecord, SharingRequest, SharingGrant,
    SecurityAlert, SecurityIncident, RiskAssessment
)
from services.encryption import EncryptionService
from services.audit import AuditService

def create_sample_pdf_content(title, patient_name, doctor_name, notes):
    """Generates synthetic medical report plaintext representation."""
    return f"""================================================================================
                    NEXAVAULT SECURE MEDICAL VAULT REPORT
================================================================================
Report Title      : {title}
Patient ID        : Confidential Record
Patient Full Name : {patient_name}
Consulting Doctor : {doctor_name}
Generation Date   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Security Level    : AES-256-GCM ENCRYPTED | ZERO-KNOWLEDGE AUDIT LOGGED
================================================================================
CLINICAL OBSERVATIONS & DIAGNOSTIC FINDINGS:
{notes}

RECOMMENDED THERAPEUTIC REGIMEN:
- Continue prescribed maintenance medication with weekly monitoring.
- Hydration, lifestyle adjustments, and follow-up consultation in 14 days.

CONFIDENTIALITY NOTICE:
This document contains Protected Health Information (PHI) under HIPAA safeguards.
Unauthorized reproduction, dissemination, or decryption is strictly prohibited.
All access transactions are cryptographically recorded in the NexaVault audit chain.
================================================================================
""".encode('utf-8')


def seed_database():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        # Clear existing tables
        db.drop_all()
        db.create_all()
        print("[1/6] Database tables created cleanly.")

        enc_service = EncryptionService()

        # -------------------------------------------------------------
        # 1. Create Core Users
        # -------------------------------------------------------------
        users_data = [
            {'email': 'admin@test.com', 'role': 'admin', 'name': 'NexaVault SecOps Admin', 'pwd': 'Admin@123'},
            {'email': 'doctor@test.com', 'role': 'doctor', 'name': 'Dr. Aarav Sharma', 'pwd': 'Doctor@123'},
            {'email': 'patient@test.com', 'role': 'patient', 'name': 'Harshita Makwana', 'pwd': 'Patient@123'},
            {'email': 'finance@test.com', 'role': 'finance', 'name': 'Ramesh Kumar (Billing Lead)', 'pwd': 'Finance@123'},
            {'email': 'staff@test.com', 'role': 'staff', 'name': 'Sunita Rao (Desk Officer)', 'pwd': 'Staff@123'},
            
            # Additional doctors for multi-doctor sharing tests
            {'email': 'dr.priya@test.com', 'role': 'doctor', 'name': 'Dr. Priya Mehta', 'pwd': 'Doctor@123'},
            {'email': 'dr.rahul@test.com', 'role': 'doctor', 'name': 'Dr. Rahul Patel', 'pwd': 'Doctor@123'},
            {'email': 'dr.ananya@test.com', 'role': 'doctor', 'name': 'Dr. Ananya Shah', 'pwd': 'Doctor@123'},
            {'email': 'dr.rohan@test.com', 'role': 'doctor', 'name': 'Dr. Rohan Desai', 'pwd': 'Doctor@123'},
            {'email': 'dr.neha@test.com', 'role': 'doctor', 'name': 'Dr. Neha Joshi', 'pwd': 'Doctor@123'},
            {'email': 'dr.kunal@test.com', 'role': 'doctor', 'name': 'Dr. Kunal Trivedi', 'pwd': 'Doctor@123'},
            {'email': 'dr.isha@test.com', 'role': 'doctor', 'name': 'Dr. Isha Verma', 'pwd': 'Doctor@123'},
            {'email': 'dr.vivek@test.com', 'role': 'doctor', 'name': 'Dr. Vivek Rao', 'pwd': 'Doctor@123'},
            {'email': 'dr.meera@test.com', 'role': 'doctor', 'name': 'Dr. Meera Iyer', 'pwd': 'Doctor@123'},
        ]

        created_users = {}
        for u in users_data:
            user_obj = User(
                email=u['email'],
                role=u['role'],
                full_name=u['name'],
                is_active=True,
                is_locked=False,
                mfa_enabled=False
            )
            user_obj.set_password(u['pwd'])
            db.session.add(user_obj)
            created_users[u['email']] = user_obj

        db.session.commit()
        print(f"[2/6] Created {len(created_users)} authentication accounts.")

        # -------------------------------------------------------------
        # 2. Create 10 Indian Doctors
        # -------------------------------------------------------------
        doctors_data = [
            {
                'id': 'D001', 'email': 'doctor@test.com', 'name': 'Dr. Aarav Sharma',
                'spec': 'General Medicine', 'dept': 'Internal Medicine',
                'qual': 'MBBS, MD (General Medicine)', 'exp': 12,
                'bio': 'Senior consultant physician specializing in preventive cardiology, metabolic health, and geriatric care.',
                'phone': '+91 98200 10001', 'avatar': 'AS'
            },
            {
                'id': 'D002', 'email': 'dr.priya@test.com', 'name': 'Dr. Priya Mehta',
                'spec': 'Cardiology', 'dept': 'Cardiology & Vascular Care',
                'qual': 'MBBS, DM (Cardiology), FACC', 'exp': 15,
                'bio': 'Interventional cardiologist with deep expertise in non-invasive coronary diagnostics and valve management.',
                'phone': '+91 98200 10002', 'avatar': 'PM'
            },
            {
                'id': 'D003', 'email': 'dr.rahul@test.com', 'name': 'Dr. Rahul Patel',
                'spec': 'Neurology', 'dept': 'Neurology Sciences',
                'qual': 'MBBS, DM (Neurology)', 'exp': 10,
                'bio': 'Specialist in neuromuscular disorders, stroke rehabilitation, and neuro-critical diagnostic imaging.',
                'phone': '+91 98200 10003', 'avatar': 'RP'
            },
            {
                'id': 'D004', 'email': 'dr.ananya@test.com', 'name': 'Dr. Ananya Shah',
                'spec': 'Dermatology', 'dept': 'Dermatology & Cosmetology',
                'qual': 'MBBS, MD (Dermatology, Venereology & Leprosy)', 'exp': 8,
                'bio': 'Clinical dermatologist focused on autoimmune dermatoses, laser interventions, and dermato-pathology.',
                'phone': '+91 98200 10004', 'avatar': 'AS'
            },
            {
                'id': 'D005', 'email': 'dr.rohan@test.com', 'name': 'Dr. Rohan Desai',
                'spec': 'Orthopedics', 'dept': 'Orthopedic Surgery & Joint Replacement',
                'qual': 'MBBS, MS (Orthopedics), MCh (Ortho)', 'exp': 14,
                'bio': 'Orthopedic surgeon leading complex arthroplasty, sports injury rehabilitation, and spinal trauma care.',
                'phone': '+91 98200 10005', 'avatar': 'RD'
            },
            {
                'id': 'D006', 'email': 'dr.neha@test.com', 'name': 'Dr. Neha Joshi',
                'spec': 'Pediatrics', 'dept': 'Pediatrics & Neonatal Care',
                'qual': 'MBBS, MD (Pediatrics), DNB', 'exp': 9,
                'bio': 'Pediatric specialist with focus on developmental pediatrics, infant nutrition, and immunization protocols.',
                'phone': '+91 98200 10006', 'avatar': 'NJ'
            },
            {
                'id': 'D007', 'email': 'dr.kunal@test.com', 'name': 'Dr. Kunal Trivedi',
                'spec': 'Gastroenterology', 'dept': 'Digestive Diseases & Endoscopy',
                'qual': 'MBBS, MD, DM (Gastroenterology)', 'exp': 11,
                'bio': 'Therapeutic endoscopist specializing in inflammatory bowel disease, hepatology, and biliary endoscopy.',
                'phone': '+91 98200 10007', 'avatar': 'KT'
            },
            {
                'id': 'D008', 'email': 'dr.isha@test.com', 'name': 'Dr. Isha Verma',
                'spec': 'Gynecology', 'dept': 'Obstetrics & High-Risk Pregnancy',
                'qual': 'MBBS, MS (Obstetrics & Gynecology), FICOG', 'exp': 13,
                'bio': 'Obstetrician and gynecologist managing high-risk pregnancies, maternal health, and reproductive endocrinology.',
                'phone': '+91 98200 10008', 'avatar': 'IV'
            },
            {
                'id': 'D009', 'email': 'dr.vivek@test.com', 'name': 'Dr. Vivek Rao',
                'spec': 'Pulmonology', 'dept': 'Respiratory Medicine & Sleep Lab',
                'qual': 'MBBS, MD (Pulmonary Medicine), FCCP', 'exp': 10,
                'bio': 'Pulmonologist and critical care physician with extensive experience in obstructive airway disease and sleep apnea.',
                'phone': '+91 98200 10009', 'avatar': 'VR'
            },
            {
                'id': 'D010', 'email': 'dr.meera@test.com', 'name': 'Dr. Meera Iyer',
                'spec': 'Endocrinology', 'dept': 'Endocrinology & Diabetology',
                'qual': 'MBBS, MD, DM (Endocrinology)', 'exp': 16,
                'bio': 'Endocrinologist specializing in complex diabetes management, thyroid disorders, and adrenal pathologies.',
                'phone': '+91 98200 10010', 'avatar': 'MI'
            }
        ]

        doctor_map = {}
        for d in doctors_data:
            doc_obj = Doctor(
                doctor_id=d['id'],
                user_id=created_users[d['email']].id,
                full_name=d['name'],
                specialization=d['spec'],
                department=d['dept'],
                qualification=d['qual'],
                experience_years=d['exp'],
                bio=d['bio'],
                contact_email=d['email'],
                phone=d['phone'],
                avatar_initials=d['avatar']
            )
            db.session.add(doc_obj)
            doctor_map[d['id']] = doc_obj

        db.session.commit()
        print(f"[3/6] Created 10 Doctor profiles.")

        # -------------------------------------------------------------
        # 3. Create 15 Indian Patients (Harshita Makwana P001 #1)
        # -------------------------------------------------------------
        patients_data = [
            {
                'id': 'P001', 'name': 'Harshita Makwana', 'dob': '1998-04-14', 'age': 28,
                'gender': 'Female', 'blood': 'B+', 'phone': '+91 98250 11001',
                'dept': 'General Medicine', 'status': 'Active', 'doc_id': 'D001',
                'user_email': 'patient@test.com'
            },
            {
                'id': 'P002', 'name': 'Kaif Saiyed', 'dob': '1992-09-22', 'age': 34,
                'gender': 'Male', 'blood': 'O+', 'phone': '+91 98250 11002',
                'dept': 'General Medicine', 'status': 'Active', 'doc_id': 'D001',
                'user_email': None
            },
            {
                'id': 'P003', 'name': 'Neel Patel', 'dob': '1981-11-05', 'age': 45,
                'gender': 'Male', 'blood': 'A+', 'phone': '+91 98250 11003',
                'dept': 'Cardiology & Vascular Care', 'status': 'Active', 'doc_id': 'D002',
                'user_email': None
            },
            {
                'id': 'P004', 'name': 'Urmish Soi', 'dob': '1974-06-18', 'age': 52,
                'gender': 'Male', 'blood': 'AB+', 'phone': '+91 98250 11004',
                'dept': 'Cardiology & Vascular Care', 'status': 'Follow-up', 'doc_id': 'D002',
                'user_email': None
            },
            {
                'id': 'P005', 'name': 'Pratham Shah', 'dob': '1997-03-30', 'age': 29,
                'gender': 'Male', 'blood': 'B-', 'phone': '+91 98250 11005',
                'dept': 'Neurology Sciences', 'status': 'Active', 'doc_id': 'D003',
                'user_email': None
            },
            {
                'id': 'P006', 'name': 'Bhadra Rupala', 'dob': '1988-08-12', 'age': 38,
                'gender': 'Female', 'blood': 'O-', 'phone': '+91 98250 11006',
                'dept': 'Neurology Sciences', 'status': 'Under Review', 'doc_id': 'D003',
                'user_email': None
            },
            {
                'id': 'P007', 'name': 'Neelkanth Patel', 'dob': '1995-01-25', 'age': 31,
                'gender': 'Male', 'blood': 'A-', 'phone': '+91 98250 11007',
                'dept': 'Dermatology & Cosmetology', 'status': 'Active', 'doc_id': 'D004',
                'user_email': None
            },
            {
                'id': 'P008', 'name': 'Arnav Yadav', 'dob': '2000-07-19', 'age': 26,
                'gender': 'Male', 'blood': 'B+', 'phone': '+91 98250 11008',
                'dept': 'Dermatology & Cosmetology', 'status': 'Active', 'doc_id': 'D004',
                'user_email': None
            },
            {
                'id': 'P009', 'name': 'Panth Patel', 'dob': '1985-05-14', 'age': 41,
                'gender': 'Male', 'blood': 'O+', 'phone': '+91 98250 11009',
                'dept': 'Orthopedic Surgery & Joint Replacement', 'status': 'Rehabilitation', 'doc_id': 'D005',
                'user_email': None
            },
            {
                'id': 'P010', 'name': 'Raju Singh', 'dob': '1968-12-03', 'age': 58,
                'gender': 'Male', 'blood': 'A+', 'phone': '+91 98250 11010',
                'dept': 'Orthopedic Surgery & Joint Replacement', 'status': 'Active', 'doc_id': 'D005',
                'user_email': None
            },
            {
                'id': 'P011', 'name': 'Ankush Nath', 'dob': '2014-04-09', 'age': 12,
                'gender': 'Male', 'blood': 'B+', 'phone': '+91 98250 11011',
                'dept': 'Pediatrics & Neonatal Care', 'status': 'Active', 'doc_id': 'D006',
                'user_email': None
            },
            {
                'id': 'P012', 'name': 'Hardik Prajapati', 'dob': '1990-10-27', 'age': 36,
                'gender': 'Male', 'blood': 'AB-', 'phone': '+91 98250 11012',
                'dept': 'Digestive Diseases & Endoscopy', 'status': 'Active', 'doc_id': 'D007',
                'user_email': None
            },
            {
                'id': 'P013', 'name': 'Sunny Mesuriya', 'dob': '1996-02-17', 'age': 30,
                'gender': 'Female', 'blood': 'O+', 'phone': '+91 98250 11013',
                'dept': 'Obstetrics & High-Risk Pregnancy', 'status': 'Maternity Care', 'doc_id': 'D008',
                'user_email': None
            },
            {
                'id': 'P014', 'name': 'Shreyash Raybole', 'dob': '1979-08-31', 'age': 47,
                'gender': 'Male', 'blood': 'A+', 'phone': '+91 98250 11014',
                'dept': 'Respiratory Medicine & Sleep Lab', 'status': 'Active', 'doc_id': 'D009',
                'user_email': None
            },
            {
                'id': 'P015', 'name': 'Yash Patel', 'dob': '1993-06-11', 'age': 33,
                'gender': 'Male', 'blood': 'B+', 'phone': '+91 98250 11015',
                'dept': 'Endocrinology & Diabetology', 'status': 'Monitoring', 'doc_id': 'D010',
                'user_email': None
            }
        ]

        for p in patients_data:
            pat_user_id = created_users[p['user_email']].id if p['user_email'] else None
            patient_obj = Patient(
                patient_id=p['id'],
                user_id=pat_user_id,
                full_name=p['name'],
                dob=p['dob'],
                age=p['age'],
                gender=p['gender'],
                blood_group=p['blood'],
                phone=p['phone'],
                department=p['dept'],
                status=p['status'],
                primary_doctor_id=p['doc_id']
            )
            db.session.add(patient_obj)
            
            # Primary assignment link
            assignment = DoctorPatientAssignment(
                doctor_id=p['doc_id'],
                patient_id=p['id'],
                is_primary=True
            )
            db.session.add(assignment)

        db.session.commit()
        print(f"[4/6] Created 15 Patients with Primary Assignments (Harshita Makwana P001 #1).")

        # -------------------------------------------------------------
        # 4. Generate & Encrypt Sample Medical Records
        # -------------------------------------------------------------
        sample_records_data = [
            {
                'rec_id': 'MR-1001',
                'patient_id': 'P001',
                'title': 'Comprehensive Metabolic Panel & Lipid Profile',
                'category': 'Lab Report',
                'doctor_name': 'Dr. Aarav Sharma',
                'notes': 'Fasting blood glucose 92 mg/dL. HbA1c 5.4%. Total cholesterol 178 mg/dL. Liver enzymes within optimal range.',
                'filename': 'P001_Metabolic_Panel.pdf'
            },
            {
                'rec_id': 'MR-1002',
                'patient_id': 'P001',
                'title': 'Abdominal Ultrasound & Diagnostic Radiology Summary',
                'category': 'Radiology Ultrasound',
                'doctor_name': 'Dr. Aarav Sharma',
                'notes': 'Normal hepatic echotexture without focal mass. Gallbladder wall regular, no calculi detected. Normal renal parenchymal thickness.',
                'filename': 'P001_Abdominal_Ultrasound.pdf'
            },
            {
                'rec_id': 'MR-1003',
                'patient_id': 'P002',
                'title': 'Routine Blood Count & Vitamin D Assessment',
                'category': 'Diagnostic Pathology',
                'doctor_name': 'Dr. Aarav Sharma',
                'notes': 'Hemoglobin 14.2 g/dL. Total leukocyte count 6,800/mcL. Serum 25-OH Vitamin D 18 ng/mL (Mild insufficiency noted, supplementation started).',
                'filename': 'P002_Routine_Hemogram.pdf'
            },
            {
                'rec_id': 'MR-1004',
                'patient_id': 'P003',
                'title': 'Echocardiogram & Cardiac Stress Test Analysis',
                'category': 'Cardiology Diagnostics',
                'doctor_name': 'Dr. Priya Mehta',
                'notes': 'Left ventricular ejection fraction 62%. Normal diastolic relaxation pattern. No inducible myocardial ischemia at 9.4 METs target workload.',
                'filename': 'P003_Stress_Echo_Report.pdf'
            }
        ]

        os.makedirs(Config.MED_RECORDS_DIR, exist_ok=True)
        dr_aarav_user = created_users['doctor@test.com']

        for s in sample_records_data:
            plaintext = create_sample_pdf_content(
                s['title'],
                "Harshita Makwana" if s['patient_id'] == 'P001' else ("Kaif Saiyed" if s['patient_id'] == 'P002' else "Neel Patel"),
                s['doctor_name'],
                s['notes']
            )
            
            # Perform AES-256-GCM Envelope Encryption
            enc_result = enc_service.encrypt_file_data(plaintext)
            
            unique_disk_name = f"{s['rec_id']}_{uuid.uuid4().hex[:8]}.enc"
            disk_path = os.path.join(Config.MED_RECORDS_DIR, unique_disk_name)
            
            with open(disk_path, 'wb') as f:
                f.write(enc_result['ciphertext'])
                
            rec_obj = MedicalRecord(
                record_id=s['rec_id'],
                patient_id=s['patient_id'],
                uploader_id=dr_aarav_user.id,
                title=s['title'],
                category=s['category'],
                original_filename=s['filename'],
                encrypted_filepath=disk_path,
                wrapped_dek=enc_result['wrapped_dek_b64'],
                dek_nonce=enc_result['dek_nonce_b64'],
                dek_tag=enc_result['dek_tag_b64'],
                file_nonce=enc_result['file_nonce_b64'],
                file_tag=enc_result['file_tag_b64'],
                sha256_hash=enc_result['sha256_hash'],
                file_size=len(plaintext),
                mime_type='application/pdf',
                description=s['notes']
            )
            db.session.add(rec_obj)

        # Sample billing record for Finance role demo
        finance_user = created_users['finance@test.com']
        billing_sample = BillingRecord(
            invoice_id='INV-2026-001',
            patient_id='P001',
            uploader_id=finance_user.id,
            title='In-Patient Diagnostic Consultation & Pathology Invoice',
            amount=3850.00,
            status='Paid',
            original_filename='INV_P001_Consultation.pdf',
            file_size=14200,
            description='Includes General Consultation fee, Comprehensive Metabolic Panel, and Radiology Scan.'
        )
        db.session.add(billing_sample)
        
        db.session.commit()
        print("[5/6] Created sample AES-256-GCM encrypted medical & billing records.")

        # -------------------------------------------------------------
        # 5. Seed HIPAA Safeguards Risk Assessment Matrix
        # -------------------------------------------------------------
        hipaa_controls = [
            {
                'id': 'AC-1', 'cat': 'Access Control', 'name': 'Unique User Identification & RBAC',
                'type': 'Technical', 'cite': '45 CFR § 164.312(a)(1)', 'status': 'Implemented',
                'notes': 'Role-based access enforced in backend code; separate roles for Admin, Doctor, Patient, Finance, Staff.'
            },
            {
                'id': 'AC-2', 'cat': 'Access Control', 'name': 'Automatic Session Termination',
                'type': 'Technical', 'cite': '45 CFR § 164.312(a)(2)(iii)', 'status': 'Implemented',
                'notes': 'Session timeout configured at 60 minutes with cookie HttpOnly protection.'
            },
            {
                'id': 'EN-1', 'cat': 'Transmission & Storage', 'name': 'AES-256-GCM Envelope Encryption',
                'type': 'Technical', 'cite': '45 CFR § 164.312(a)(2)(iv)', 'status': 'Implemented',
                'notes': 'Zero-leakage envelope encryption with ephemeral DEKs wrapped by Master KEK.'
            },
            {
                'id': 'AU-1', 'cat': 'Audit Controls', 'name': 'Tamper-Evident Hash-Linked Audit Trail',
                'type': 'Technical', 'cite': '45 CFR § 164.312(b)', 'status': 'Implemented',
                'notes': 'Sequential SHA-256 cryptographic chain recording all logins, decryptions, sharing, and denials.'
            },
            {
                'id': 'IN-1', 'cat': 'Data Integrity', 'name': 'Cryptographic Tag & SHA-256 Verification',
                'type': 'Technical', 'cite': '45 CFR § 164.312(c)(1)', 'status': 'Implemented',
                'notes': 'Files are checked against trusted baseline SHA-256 hash prior to streaming.'
            },
            {
                'id': 'AD-1', 'cat': 'Administrative', 'name': 'Security Incident Response Protocol',
                'type': 'Administrative', 'cite': '45 CFR § 164.308(a)(6)', 'status': 'Implemented',
                'notes': 'Automated triage from detection engine to SecurityIncidents with status tracking.'
            },
            {
                'id': 'CP-1', 'cat': 'Contingency Planning', 'name': 'Data Backup & Disaster Recovery Plan',
                'type': 'Administrative', 'cite': '45 CFR § 164.308(a)(7)', 'status': 'Implemented',
                'notes': 'Encrypted snapshot mechanism with SHA-256 integrity verification.'
            },
            {
                'id': 'PH-1', 'cat': 'Physical Safeguards', 'name': 'Workstation Security & Key Isolation',
                'type': 'Physical', 'cite': '45 CFR § 164.310(b)', 'status': 'Implemented',
                'notes': 'Cryptographic keys separated from SQLite database and excluded from public static web roots.'
            }
        ]

        for hc in hipaa_controls:
            ra = RiskAssessment(
                control_id=hc['id'],
                category=hc['cat'],
                control_name=hc['name'],
                safeguard_type=hc['type'],
                hipaa_citation=hc['cite'],
                status=hc['status'],
                notes=hc['notes']
            )
            db.session.add(ra)

        # -------------------------------------------------------------
        # 6. Initialize Audit Chain & Sample Baseline Security Alerts
        # -------------------------------------------------------------
        db.session.commit()
        
        # Genesis block and initial audit logs
        admin_user = created_users['admin@test.com']
        AuditService.log_event(
            event_type='SYSTEM_INIT',
            action='Initialized NexaVault Cryptographic Environment',
            status='SUCCESS',
            target_resource='NexaVault Database & Master Key',
            details='15 Patients, 10 Doctors, AES-256-GCM cipher suite and HIPAA controls initialized.',
            user=admin_user
        )
        
        AuditService.log_event(
            event_type='RECORD_ENCRYPTED',
            action='Uploaded and encrypted MR-1001',
            status='SUCCESS',
            target_resource='MR-1001 (P001)',
            details='AES-256-GCM envelope encryption applied. SHA-256 baseline recorded.',
            user=dr_aarav_user
        )

        # Baseline demo alert
        baseline_alert = SecurityAlert(
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=45),
            rule_name='BASELINE_SCAN_CLEAN',
            severity='Low',
            risk_score_impact=5,
            source_ip='127.0.0.1',
            user_id=admin_user.id,
            user_email=admin_user.email,
            details='Routine cryptographic integrity scan completed with zero anomalies.',
            status='Resolved'
        )
        db.session.add(baseline_alert)
        db.session.commit()
        
        print("[6/6] Audit trail seeded and verified. Seed complete successfully!")

if __name__ == '__main__':
    seed_database()
