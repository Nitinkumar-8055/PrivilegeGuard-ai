import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def _load_env():
    env_file = BASE_DIR / '.env'
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as ef:
            for line in ef:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k not in os.environ:
                        os.environ[k] = v

_load_env()

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "privilegeguard-dev-secret-key-2026-safe")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'privilegeguard.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Ingestion constraints
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    MAX_RECORDS_PER_UPLOAD = 10000
    ALLOWED_EXTENSIONS = {"json", "csv"}
    
    # SQLite Engine configuration
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "timeout": 30.0,
            "check_same_thread": False
        }
    }

    # Security Rule Configs
    FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", 3))
    FAILED_LOGIN_WINDOW_MINUTES = int(os.environ.get("FAILED_LOGIN_WINDOW_MINUTES", 15))
    PRIVILEGE_CHANGE_WINDOW_MINUTES = int(os.environ.get("PRIVILEGE_CHANGE_WINDOW_MINUTES", 30))
    
    # Policy lists for detection
    SENSITIVE_ROLES = [
        "admin",
        "administrator",
        "root",
        "secops_admin",
        "domain_admin",
        "global_admin",
        "security_lead"
    ]
    
    AUTHORIZED_ROLE_MANAGERS = [
        "secops_admin",
        "superadmin",
        "identity_governance_service",
        "it_directory_sync"
    ]
    
    SENSITIVE_RESOURCES = [
        "/api/v1/vault/keys",
        "s3://financial-records",
        "/etc/shadow",
        "database://customer_pii",
        "hrms://executive_salaries",
        "ad://domain_controllers",
        "cloud://iam-root-keys",
        "auth://mfa_tokens"
    ]

    # Notification & Alert Management Configuration
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))
    SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "SSL")
    SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "nk8055444@gmail.com")
    EMAIL_NOTIFICATIONS_ENABLED = os.environ.get("EMAIL_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")
    INAPP_NOTIFICATIONS_ENABLED = os.environ.get("INAPP_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")
    EMAIL_SEVERITIES = [s.strip().lower() for s in os.environ.get("EMAIL_SEVERITIES", "high,critical").split(",") if s.strip()]
    INAPP_SEVERITIES = [s.strip().lower() for s in os.environ.get("INAPP_SEVERITIES", "low,medium,high,critical").split(",") if s.strip()]

    # AI / Ollama Config
    OLLAMA_API_URL = os.environ.get(
        "OLLAMA_API_URL",
        "http://localhost:11434/api/generate"
    )
    OLLAMA_MODEL = os.environ.get(
        "OLLAMA_MODEL",
        "qwen2.5:3b"
    )
    OLLAMA_TIMEOUT_SECONDS = int(
        os.environ.get("OLLAMA_TIMEOUT_SECONDS", 120)
    )

class TestConfig(Config):
    """Configuration for automated testing."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    from sqlalchemy.pool import StaticPool
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "check_same_thread": False
        },
        "poolclass": StaticPool
    }
    WTF_CSRF_ENABLED = False
    # Notification overrides for testing
    SMTP_EMAIL = "test-sender@gmail.com"
    SMTP_PASSWORD = "test-app-password"
    ADMIN_EMAIL = "nk8055444@gmail.com"
    EMAIL_NOTIFICATIONS_ENABLED = True
    INAPP_NOTIFICATIONS_ENABLED = True
    # Ensure automated tests test deterministic fallback quickly without hanging on live Ollama
    OLLAMA_API_URL = "http://127.0.0.1:9999/api/generate"
    OLLAMA_TIMEOUT_SECONDS = 1
