import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

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
    # Ensure automated tests test deterministic fallback quickly without hanging on live Ollama
    OLLAMA_API_URL = "http://127.0.0.1:9999/api/generate"
    OLLAMA_TIMEOUT_SECONDS = 1

