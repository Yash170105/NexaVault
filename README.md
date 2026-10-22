# NexaVault — Secure Medical Records & Threat Monitoring Platform

> **Secure Medical Records. Controlled Access. Trusted Care.**  
> A cybersecurity-focused healthcare platform engineered for zero-trust medical record storage, patient-governed consent sharing, cryptographic integrity verification, and tamper-evident audit logging.

---

## 🛡️ Core Highlights & Specifications

| Dimension | Specification |
| :--- | :--- |
| **Concept** | Encrypted Medical Record Vault + Controlled Cross-Consultation Sharing + Cybersecurity Threat Monitoring |
| **Backend** | Python 3, Flask, SQLAlchemy, Werkzeug |
| **Database** | Relational SQLite 3 (`instance/nexavault.db`) |
| **File Encryption** | **AES-256-GCM** envelope encryption with ephemeral DEKs wrapped by Master KEK |
| **Integrity Baseline** | **SHA-256** checksums + AES-GCM 16-byte authentication tags |
| **Forensic Audit Log** | Tamper-evident sequential **SHA-256 hash chain** linked to genesis block |
| **Access Control (RBAC)**| Strict least-privilege backend enforcement (Admin denied clinical decryption; Finance denied clinical records) |
| **Synthetic Dataset** | Exactly **15 Patients** (Harshita Makwana `P001` #1) and **10 Indian Doctors** (`D001` - `D010`) |
| **Design Palette** | Warm Ivory/Sand Theme: Beige (`#EAE7DC`), Sand (`#D8C3A5`), Stone Grey (`#8E8D8A`), Coral (`#E98074`), Accent Red (`#E85A4F`) |

---

## 👥 Demo User Accounts (Pre-Seeded)

The application provides a **Viva Quick Switcher Bar** at the top of every page, allowing instant one-click persona switching without re-typing passwords.

| Role | Demo Email | Demo Password | Persona & Responsibility |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@test.com` | `Admin@123` | SecOps Admin (Manages users, monitors threat engine, investigates incidents; **cannot** decrypt clinical records) |
| **Doctor** | `doctor@test.com` | `Doctor@123` | Dr. Aarav Sharma (General Medicine; assigned to Harshita Makwana & Kaif Saiyed) |
| **Patient** | `patient@test.com` | `Patient@123` | Harshita Makwana (`P001`; owns records, approves/rejects consent, revokes grants) |
| **Finance** | `finance@test.com` | `Finance@123` | Ramesh Kumar (Billing lead; manages invoices, strictly denied clinical reports) |
| **Staff** | `staff@test.com` | `Staff@123` | Sunita Rao (Front desk triage; read-only demographics, excluded from clinical/billing data) |

---

## 🏥 Complete 15 Patient Dataset & Assignments

Harshita Makwana (`P001`) is guaranteed to appear first in all default directory views:

1. **`P001`** — **Harshita Makwana** (28 yrs, `B+`, Primary Doctor: **Dr. Aarav Sharma**)
2. **`P002`** — **Kaif Saiyed** (34 yrs, `O+`, Primary Doctor: **Dr. Aarav Sharma**)
3. **`P003`** — **Neel Patel** (45 yrs, `A+`, Primary Doctor: **Dr. Priya Mehta**)
4. **`P004`** — **Urmish Soi** (52 yrs, `AB+`, Primary Doctor: **Dr. Priya Mehta**)
5. **`P005`** — **Pratham Shah** (29 yrs, `B-`, Primary Doctor: **Dr. Rahul Patel**)
6. **`P006`** — **Bhadra Rupala** (38 yrs, `O-`, Primary Doctor: **Dr. Rahul Patel**)
7. **`P007`** — **Neelkanth Patel** (31 yrs, `A-`, Primary Doctor: **Dr. Ananya Shah**)
8. **`P008`** — **Arnav Yadav** (26 yrs, `B+`, Primary Doctor: **Dr. Ananya Shah**)
9. **`P009`** — **Panth Patel** (41 yrs, `O+`, Primary Doctor: **Dr. Rohan Desai**)
10. **`P010`** — **Raju Singh** (58 yrs, `A+`, Primary Doctor: **Dr. Rohan Desai**)
11. **`P011`** — **Ankush Nath** (12 yrs, `B+`, Primary Doctor: **Dr. Neha Joshi**)
12. **`P012`** — **Hardik Prajapati** (36 yrs, `AB-`, Primary Doctor: **Dr. Kunal Trivedi**)
13. **`P013`** — **Sunny Mesuriya** (30 yrs, `O+`, Primary Doctor: **Dr. Isha Verma**)
14. **`P014`** — **Shreyash Raybole** (47 yrs, `A+`, Primary Doctor: **Dr. Vivek Rao**)
15. **`P015`** — **Yash Patel** (33 yrs, `B+`, Primary Doctor: **Dr. Meera Iyer**)

---

## 🩺 Ten Indian Doctors & Specializations

- **`D001`** — **Dr. Aarav Sharma** · General Medicine (Internal Medicine)
- **`D002`** — **Dr. Priya Mehta** · Cardiology (Cardiology & Vascular Care)
- **`D003`** — **Dr. Rahul Patel** · Neurology (Neurology Sciences)
- **`D004`** — **Dr. Ananya Shah** · Dermatology (Dermatology & Cosmetology)
- **`D005`** — **Dr. Rohan Desai** · Orthopedics (Orthopedic Surgery & Joint Replacement)
- **`D006`** — **Dr. Neha Joshi** · Pediatrics (Pediatrics & Neonatal Care)
- **`D007`** — **Dr. Kunal Trivedi** · Gastroenterology (Digestive Diseases & Endoscopy)
- **`D008`** — **Dr. Isha Verma** · Gynecology (Obstetrics & High-Risk Pregnancy)
- **`D009`** — **Dr. Vivek Rao** · Pulmonology (Respiratory Medicine & Sleep Lab)
- **`D010`** — **Dr. Meera Iyer** · Endocrinology (Endocrinology & Diabetology)

---

## 🔐 Cryptographic Architecture & Flow

```
+-----------------------------------------------------------------------+
|                         FILE UPLOAD WORKFLOW                          |
| Plaintext File -> Compute SHA-256 Baseline -> Generate 32-byte DEK    |
|   -> Encrypt via AES-256-GCM (DEK + Nonce -> Ciphertext + Tag)        |
|   -> Wrap DEK with Master KEK via AES-256-GCM                         |
|   -> Save ciphertext to encrypted_files/med_records/<uuid>.enc        |
|   -> Store wrapped DEK, nonces, tags, SHA-256 in SQLite database      |
+-----------------------------------------------------------------------+
                                   |
+-----------------------------------------------------------------------+
|                        FILE DOWNLOAD & VERIFY                         |
| Request -> RBAC & Consent Check -> Unwrap DEK with Master KEK         |
|   -> Decrypt Ciphertext verifying 16-byte GCM Tag                     |
|   -> Compute SHA-256 of decrypted bytes and compare with baseline     |
|   -> If Mismatch: Trigger CRITICAL alert, abort serve with HTTP 500   |
|   -> If Verified: Stream decrypted file directly to memory buffer     |
+-----------------------------------------------------------------------+
```

---

## ⚡ Step-by-Step Viva Demonstration Flow

1. **Admin Login & Patient Cohort**:
   - Click **Admin** in the top quick switcher bar.
   - Show the 15-patient dataset with **Harshita Makwana (`P001`) leading the list**.
   - Show 10 doctor profiles, threat risk gauge (0-100), and account governance.

2. **Doctor Login & Encrypted Upload**:
   - Click **Doctor** in the quick switcher (Dr. Aarav Sharma).
   - View assigned patients (Harshita & Kaif).
   - Upload a new diagnostic report. Point out the encryption process (AES-256-GCM envelope encryption, unique DEK generation, trusted SHA-256 baseline).

3. **Patient Login & Consent Control**:
   - Click **Patient** (Harshita Makwana).
   - View own medical documents.
   - Click **Decrypt & Download** on `MR-1001` (demonstrates in-memory decryption and verified delivery).
   - Show transparent audit history of who accessed her reports.

4. **Consent-Gated Sharing & Revocation**:
   - Switch to **Doctor** and submit a sharing request to refer Harshita's `MR-1001` to Dr. Priya Mehta (Cardiology).
   - Switch to **Patient**: see pending consent request card; click **Approve (48h)**.
   - Show generated high-entropy token.
   - Demonstrate revocation: click **Revoke**; immediately after, future download attempts fail.

5. **Finance Role Clinical Denial Demo**:
   - Click **Finance**.
   - View invoices.
   - Click the red button: **"Attempt Medical Record Decryption (Expect 403 Denial)"**.
   - Show that the backend returns HTTP 403 Forbidden, logs the attempt, and triggers an `UNAUTHORIZED_RECORD_ACCESS` / `UNAUTHORIZED_ROLE_PROBE` security alert.

6. **Forensic Integrity Verification & Tampering Simulator**:
   - Switch back to **Admin**.
   - In the **Viva Defense Simulator**, click **"Simulate File Bit-Flip (MR-1001)"**.
   - Now try downloading or verifying `MR-1001` — the AES-GCM tag check or SHA-256 check fails instantly with a **Critical Security Alert**!
   - Click **"Simulate Audit Entry Mutation"** and then click **"Verify Cryptographic Chain"** — the verifier pinpoints the exact tampered row number!
   - Click **"Reset Baseline"** to clean all test data back to pristine state.

7. **HIPAA Controls Matrix**:
   - Navigate to `/risk-assessment` to show examiners the complete mapping of Technical, Administrative, and Physical controls to 45 CFR citations.

---

## 🚀 How to Run Locally

```bash
# 1. Navigate to the project directory
cd C:\Users\Yash\.gemini\antigravity\scratch\NexaVault

# 2. Seed database with 15 patients, 10 doctors, and encrypted records
python seed_data.py

# 3. Run the automated test suite
python -m unittest discover -s tests -v

# 4. Start the Flask server
python app.py
```

Then open your browser at **http://127.0.0.1:5000**.
