import os
import zipfile
import hashlib
from datetime import datetime, timezone
from config import Config
from models import db
from services.audit import AuditService

class BackupService:
    @classmethod
    def create_encrypted_backup(cls, admin_user=None):
        """
        Creates a timestamped contingency backup snapshot of database & encrypted files (HIPAA § 164.308(a)(7)).
        """
        os.makedirs(Config.BACKUPS_DIR, exist_ok=True)
        timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        backup_filename = f"nexavault_snapshot_{timestamp_str}.zip"
        backup_filepath = os.path.join(Config.BACKUPS_DIR, backup_filename)
        
        db_path = os.path.join(Config.INSTANCE_DIR, 'nexavault.db')
        
        with zipfile.ZipFile(backup_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.exists(db_path):
                zipf.write(db_path, arcname='instance/nexavault.db')
            
            # Archive encrypted files (without leaking plaintext)
            for root, dirs, files in os.walk(Config.ENCRYPTED_FILES_DIR):
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, Config.BASE_DIR)
                    zipf.write(full_p, arcname=rel_p)
                    
        # Calculate backup SHA-256
        with open(backup_filepath, 'rb') as f:
            backup_sha256 = hashlib.sha256(f.read()).hexdigest()
            
        file_size = os.path.getsize(backup_filepath)
        
        AuditService.log_event(
            event_type='CONTINGENCY_BACKUP',
            action=f"Created backup snapshot {backup_filename}",
            status='SUCCESS',
            target_resource=backup_filename,
            details=f"Size: {file_size} bytes | SHA256: {backup_sha256}",
            user=admin_user
        )
        
        return {
            'filename': backup_filename,
            'filepath': backup_filepath,
            'size': file_size,
            'sha256': backup_sha256,
            'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }

    @classmethod
    def list_backups(cls):
        os.makedirs(Config.BACKUPS_DIR, exist_ok=True)
        backups = []
        for f in os.listdir(Config.BACKUPS_DIR):
            if f.endswith('.zip'):
                p = os.path.join(Config.BACKUPS_DIR, f)
                size = os.path.getsize(p)
                mtime = os.path.getmtime(p)
                dt = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                backups.append({
                    'filename': f,
                    'size': f"{size / 1024:.1f} KB",
                    'timestamp': dt
                })
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        return backups
