from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: Optional[str] = None
    impact: str
    remediation: str
    references: List[str] = Field(default_factory=list)
    manual_check: Optional[str] = None  # R6-C5: passive verification hint when no module exists

class MetasploitSuggestion(BaseModel):
    id: str
    module_path: str
    module_type: str
    title: str
    description: str
    trigger_reason: str
    confidence: str
    verification_command: str
    references: List[str] = Field(default_factory=list)
    intrusive: bool = False  # R4-11

class SSLInfo(BaseModel):
    has_ssl: bool = False
    valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires_in_days: Optional[int] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class TechInfo(BaseModel):
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "Medium"

class ScanSummary(BaseModel):
    score: int = 100
    grade: str = "A"
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class ScanRequest(BaseModel):
    url: str
    scan_recon: bool = True
    scan_ssl: bool = True
    scan_headers: bool = True
    timeout: int = 10

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    hostname: str
    ip_address: Optional[str] = None
    scan_time: str
    duration_seconds: float
    status: str = "completed"
    error: Optional[str] = None
    summary: Optional[ScanSummary] = None  # R4-11: Optional
    findings: List[Finding] = Field(default_factory=list)
    headers_analyzed: Dict[str, Any] = Field(default_factory=dict)
    ssl_info: Optional[SSLInfo] = None
    technologies: List[TechInfo] = Field(default_factory=list)
    metasploit_suggestions: List[MetasploitSuggestion] = Field(default_factory=list)
    recon_items: List[Dict[str, Any]] = Field(default_factory=list)
    diff: Optional[Dict[str, Any]] = None