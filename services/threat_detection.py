from datetime import datetime, timezone, timedelta
from models import db, SecurityAlert, SecurityIncident, AuditLog, User
from services.audit import AuditService

class ThreatDetectionService:
    @staticmethod
    def calculate_system_risk_score():
        """
        Calculates dynamic system risk score (0-100) based on unresolved security alerts
        within the past 24 hours.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        active_alerts = SecurityAlert.query.filter(
            SecurityAlert.timestamp >= cutoff,
            SecurityAlert.status.in_(['Open', 'Investigating'])
        ).all()
        
        score = 0
        severity_weights = {
            'Low': 5,
            'Medium': 15,
            'High': 25,
            'Critical': 40
        }
        
        for alert in active_alerts:
            score += severity_weights.get(alert.severity, 10)
            
        score = min(score, 100)
        
        if score < 20:
            level = "LOW / SECURE"
            color = "#2e7d32"
        elif score < 50:
            level = "GUARDED"
            color = "#ed6c02"
        elif score < 75:
            level = "ELEVATED RISK"
            color = "#e65100"
        else:
            level = "CRITICAL / SEVERE"
            color = "#d32f2f"
            
        return {
            'score': score,
            'level': level,
            'color': color,
            'active_alert_count': len(active_alerts)
        }

    @classmethod
    def trigger_alert(cls, rule_name: str, severity: str, details: str,
                      user=None, ip_address: str = "127.0.0.1"):
        """
        Generates a security alert, updates risk metrics, and auto-spawns an incident
        for High or Critical severity events.
        """
        impact_map = {'Low': 5, 'Medium': 15, 'High': 25, 'Critical': 40}
        risk_impact = impact_map.get(severity, 10)
        
        now = datetime.now(timezone.utc)
        user_id = user.id if user and hasattr(user, 'id') else None
        user_email = user.email if user and hasattr(user, 'email') else None
        
        alert = SecurityAlert(
            timestamp=now,
            rule_name=rule_name,
            severity=severity,
            risk_score_impact=risk_impact,
            source_ip=ip_address,
            user_id=user_id,
            user_email=user_email,
            details=details,
            status='Open'
        )
        db.session.add(alert)
        db.session.flush() # get alert.id
        
        # High or Critical severity alerts automatically trigger an official Security Incident
        incident = None
        if severity in ['High', 'Critical']:
            incident_count = SecurityIncident.query.count() + 1
            inc_code = f"INC-{now.strftime('%Y')}-{incident_count:03d}"
            incident = SecurityIncident(
                incident_number=inc_code,
                alert_id=alert.id,
                title=f"Automated Triage: {rule_name.replace('_', ' ').title()}",
                severity=severity,
                status='Open',
                assigned_to='SecOps Lead',
                actions_taken=f'Alert triggered from {ip_address}. Policy enforcement active.',
                notes=details,
                created_at=now
            )
            db.session.add(incident)
            
        # Log to tamper-evident audit trail
        AuditService.log_event(
            event_type='SECURITY_ALERT',
            action=f"Triggered Rule: {rule_name}",
            status='ALERT_' + severity.upper(),
            target_resource=f"Rule: {rule_name}",
            details=f"Severity: {severity} | Details: {details}",
            user=user,
            ip_address=ip_address
        )
        
        db.session.commit()
        return alert

    @classmethod
    def check_failed_logins(cls, user: User, ip_address: str):
        """Rule 1: Repeated failed logins"""
        if not user:
            return
        user.failed_login_count = (user.failed_login_count or 0) + 1
        db.session.commit()
        
        if user.failed_login_count >= 3:
            cls.trigger_alert(
                rule_name='REPEATED_FAILED_LOGIN',
                severity='Medium',
                details=f"Account {user.email} experienced {user.failed_login_count} consecutive failed login attempts.",
                user=user,
                ip_address=ip_address
            )

    @classmethod
    def check_unauthorized_access(cls, user, target_resource: str, ip_address: str, reason: str = "Access Forbidden"):
        """Rule 2: Unauthorized record access / Role probe"""
        cls.trigger_alert(
            rule_name='UNAUTHORIZED_RECORD_ACCESS',
            severity='High',
            details=f"User {user.email if user else 'Anonymous'} attempted unauthorized access to {target_resource}. Reason: {reason}",
            user=user,
            ip_address=ip_address
        )

    @classmethod
    def check_bulk_downloads(cls, user, ip_address: str):
        """Rule 3: Unusual bulk downloads within 5 minutes"""
        if not user:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_downloads = AuditLog.query.filter(
            AuditLog.user_id == user.id,
            AuditLog.event_type == 'FILE_DOWNLOAD',
            AuditLog.timestamp >= cutoff
        ).count()
        
        if recent_downloads >= 4:  # At 5th attempt
            cls.trigger_alert(
                rule_name='UNUSUAL_BULK_DOWNLOADS',
                severity='High',
                details=f"Account {user.email} initiated {recent_downloads + 1} file downloads within a 5-minute window.",
                user=user,
                ip_address=ip_address
            )

    @classmethod
    def check_integrity_failure(cls, record_id: str, filename: str, details: str, user=None, ip_address: str = "127.0.0.1"):
        """Rule 5: Cryptographic Integrity / Hash Mismatch Detected"""
        cls.trigger_alert(
            rule_name='FILE_INTEGRITY_MISMATCH',
            severity='Critical',
            details=f"Decryption integrity verification failed for Record [{record_id}] ({filename}). Evidence: {details}",
            user=user,
            ip_address=ip_address
        )
