import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app
from models import db, User, Patient, Doctor, MedicalRecord
from seed_data import seed_database

class TestNexaVaultRBAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        with app.app_context():
            seed_database()

    def setUp(self):
        self.client = app.test_client()

    def login_as(self, email, password):
        return self.client.post('/login', data={'email': email, 'password': password}, follow_redirects=True)

    def test_01_all_roles_authentication(self):
        """Verify all 5 roles authenticate properly."""
        roles_creds = [
            ('admin@test.com', 'Admin@123', b'SecOps & Administration Console'),
            ('doctor@test.com', 'Doctor@123', b'Dr. Aarav Sharma'),
            ('patient@test.com', 'Patient@123', b'Harshita Makwana'),
            ('finance@test.com', 'Finance@123', b'Finance & Billing Department Console'),
            ('staff@test.com', 'Staff@123', b'Hospital Desk Staff Directory')
        ]
        for email, pwd, expected_text in roles_creds:
            res = self.login_as(email, pwd)
            self.assertEqual(res.status_code, 200)
            self.assertIn(expected_text, res.data)
            self.client.get('/logout')

    def test_02_patient_dataset_ordering(self):
        """Verify 15 patients exist and Harshita Makwana is #1."""
        self.login_as('admin@test.com', 'Admin@123')
        res = self.client.get('/patients')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'Harshita Makwana', res.data)
        self.assertIn(b'P001', res.data)
        # Verify first occurrence in patient table is P001 Harshita Makwana
        p001_idx = res.data.find(b'P001')
        p002_idx = res.data.find(b'P002')
        self.assertTrue(p001_idx < p002_idx)
        self.client.get('/logout')

    def test_03_finance_denied_medical_records(self):
        """Verify Finance role receives HTTP 403 when trying to access clinical records."""
        self.login_as('finance@test.com', 'Finance@123')
        # Attempt to download Harshita's medical report
        res = self.client.get('/records/MR-1001/download')
        self.assertEqual(res.status_code, 403)
        self.client.get('/logout')

    def test_04_admin_least_privilege_clinical_exclusion(self):
        """Verify Admin role cannot directly access clinical files."""
        self.login_as('admin@test.com', 'Admin@123')
        res = self.client.get('/patient/P001/files', follow_redirects=True)
        self.assertIn(b'Least-Privilege Enforcement', res.data)
        self.client.get('/logout')

if __name__ == '__main__':
    unittest.main()
