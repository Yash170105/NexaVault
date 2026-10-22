import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'nexavault-super-secret-production-session-key-2026'
    
    # Instance directory for database and key
    INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    
    # SQLite Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(INSTANCE_DIR, "nexavault.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Master Encryption Key (KEK) Path
    MASTER_KEY_PATH = os.path.join(INSTANCE_DIR, 'master.key')
    
    # Encrypted File Storage
    ENCRYPTED_FILES_DIR = os.path.join(BASE_DIR, 'encrypted_files')
    MED_RECORDS_DIR = os.path.join(ENCRYPTED_FILES_DIR, 'med_records')
    BILLING_DIR = os.path.join(ENCRYPTED_FILES_DIR, 'billing')
    BACKUPS_DIR = os.path.join(BASE_DIR, 'backups')
    
    # Max content length (16 MB)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Session Security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # SESSION_COOKIE_SECURE = False for localhost development
