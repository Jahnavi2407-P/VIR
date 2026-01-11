"""
Configuration settings for Ransomware Behavior Analyzer
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Ransomware Behavior Analyzer"
    DEBUG: bool = True
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    UPLOAD_DIR: str = str(Path(__file__).parent.parent / "uploads")
    REPORTS_DIR: str = str(Path(__file__).parent.parent / "reports")
    YARA_RULES_DIR: str = str(Path(__file__).parent.parent / "yara_rules")
    LOGS_DIR: str = str(Path(__file__).parent.parent / "logs")
    
    # Database
    DATABASE_URL: str = "sqlite:///./ransomware_analyzer.db"
    
    # Redis (optional for task queue)
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    
    # Analysis settings
    ANALYSIS_TIMEOUT: int = 300  # 5 minutes
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100 MB
    
    # Sandbox settings
    SANDBOX_ENABLED: bool = True
    SANDBOX_TYPE: str = "qemu"  # qemu, virtualbox, docker
    SANDBOX_TIMEOUT: int = 120  # 2 minutes
    SANDBOX_SNAPSHOT: str = "clean_snapshot"
    
    # VM Configuration
    VM_NAME: str = "malware_sandbox"
    VM_MEMORY: int = 2048  # MB
    VM_CPUS: int = 2
    VM_DISK_IMAGE: str = "windows10_sandbox.qcow2"
    
    # Network simulation
    INETSIM_ENABLED: bool = True
    INETSIM_IP: str = "192.168.100.1"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    API_KEY: Optional[str] = None
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Create required directories
for directory in [settings.UPLOAD_DIR, settings.REPORTS_DIR, settings.LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)
