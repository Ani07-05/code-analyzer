"""
Data Models for Security Reports
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any


class RiskLevel(Enum):
    """Risk levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """Categories of security vulnerabilities"""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    ACCESS_CONTROL = "access_control"
    SECURITY_CONFIG = "security_config"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    LOGGING_MONITORING = "logging_monitoring"


@dataclass
class StackOverflowCitation:
    """Stack Overflow citation for vulnerability fix"""
    question_id: int
    title: str
    url: str
    score: int
    answer_count: int
    relevance_score: float
    tags: List[str] = field(default_factory=list)
    accepted_answer: bool = False
    creation_date: Optional[datetime] = None
    
    def __str__(self) -> str:
        return f"SO#{self.question_id}: {self.title} (Score: {self.score})"


@dataclass
class CodeSnippet:
    """Code snippet with vulnerability context"""
    file_path: Path
    line_start: int
    line_end: int
    content: str
    language: str
    
    def get_line_range(self) -> str:
        if self.line_start == self.line_end:
            return f"Line {self.line_start}"
        return f"Lines {self.line_start}-{self.line_end}"


@dataclass
class VulnerabilityFinding:
    """Detailed vulnerability finding"""
    # Basic identification
    vulnerability_id: str
    title: str
    description: str
    category: VulnerabilityCategory
    risk_level: RiskLevel
    
    # Location information
    file_path: Path
    line_start: int
    line_end: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    
    # Technical details
    vulnerable_code: CodeSnippet = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # AI Analysis results
    ai_confidence: float = 0.0
    false_positive_probability: float = 0.0
    business_impact: str = ""
    
    # Fix recommendations
    recommended_fix: str = ""
    fix_code_example: str = ""
    stack_overflow_citations: List[StackOverflowCitation] = field(default_factory=list)
    
    # Additional context
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)
    detected_by: List[str] = field(default_factory=list)  # Which phases detected it
    
    def get_risk_indicator(self) -> str:
        """Get indicator for risk level"""
        indicator_map = {
            RiskLevel.CRITICAL: "CRITICAL",
            RiskLevel.HIGH: "HIGH", 
            RiskLevel.MEDIUM: "MEDIUM",
            RiskLevel.LOW: "LOW",
            RiskLevel.INFO: "INFO"
        }
        return indicator_map.get(self.risk_level, "UNKNOWN")
    
    def get_risk_color(self) -> str:
        """Get CSS color for risk level"""
        color_map = {
            RiskLevel.CRITICAL: "#FF0000",
            RiskLevel.HIGH: "#FF4500",
            RiskLevel.MEDIUM: "#FFA500", 
            RiskLevel.LOW: "#32CD32",
            RiskLevel.INFO: "#1E90FF"
        }
        return color_map.get(self.risk_level, "#666666")


@dataclass
class LanguageStats:
    """Statistics for a programming language"""
    language: str
    file_count: int
    line_count: int
    vulnerability_count: int
    frameworks: List[str] = field(default_factory=list)


@dataclass
class FrameworkInfo:
    """Information about detected frameworks"""
    name: str
    version: Optional[str] = None
    file_count: int = 0
    vulnerability_count: int = 0
    security_features: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    """Complete security analysis report"""
    # Report metadata
    report_id: str
    title: str
    generated_at: datetime
    scan_duration: float
    
    # Target information
    target_path: Path
    total_files_scanned: int
    total_lines_scanned: int
    
    # Language and framework detection
    languages_detected: List[LanguageStats] = field(default_factory=list)
    frameworks_detected: List[FrameworkInfo] = field(default_factory=list)
    
    # Vulnerability findings
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    
    # Summary statistics
    vulnerability_counts: Dict[RiskLevel, int] = field(default_factory=dict)
    category_counts: Dict[VulnerabilityCategory, int] = field(default_factory=dict)
    
    # Analysis metadata
    phases_completed: List[str] = field(default_factory=list)
    ai_analysis_enabled: bool = False
    stack_overflow_citations_count: int = 0
    
    def __post_init__(self):
        """Calculate derived statistics"""
        self.vulnerability_counts = {level: 0 for level in RiskLevel}
        self.category_counts = {cat: 0 for cat in VulnerabilityCategory}
        
        for vuln in self.vulnerabilities:
            self.vulnerability_counts[vuln.risk_level] += 1
            self.category_counts[vuln.category] += 1
        
        self.stack_overflow_citations_count = sum(
            len(vuln.stack_overflow_citations) for vuln in self.vulnerabilities
        )
    
    def get_total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities"""
        return len(self.vulnerabilities)
    
    def get_critical_and_high_count(self) -> int:
        """Get count of critical and high risk vulnerabilities"""
        return (self.vulnerability_counts.get(RiskLevel.CRITICAL, 0) + 
                self.vulnerability_counts.get(RiskLevel.HIGH, 0))
    
    def get_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        if not self.vulnerabilities:
            return 0.0
        
        weights = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 4.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.INFO: 1.0
        }
        
        total_score = sum(
            count * weights.get(level, 0) 
            for level, count in self.vulnerability_counts.items()
        )
        
        # Normalize to 0-100 scale
        max_possible = len(self.vulnerabilities) * weights[RiskLevel.CRITICAL]
        return min(100.0, (total_score / max_possible) * 100.0) if max_possible > 0 else 0.0
    
    def get_top_vulnerabilities(self, limit: int = 10) -> List[VulnerabilityFinding]:
        """Get top vulnerabilities by risk level and AI confidence"""
        return sorted(
            self.vulnerabilities,
            key=lambda v: (
                list(RiskLevel).index(v.risk_level),  # Risk level priority
                -v.ai_confidence,  # Higher confidence first
                -len(v.stack_overflow_citations)  # More citations first
            )
        )[:limit]
    
    def get_vulnerabilities_by_file(self) -> Dict[Path, List[VulnerabilityFinding]]:
        """Group vulnerabilities by file"""
        file_groups = {}
        for vuln in self.vulnerabilities:
            if vuln.file_path not in file_groups:
                file_groups[vuln.file_path] = []
            file_groups[vuln.file_path].append(vuln)
        
        # Sort vulnerabilities within each file by line number
        for file_path in file_groups:
            file_groups[file_path].sort(key=lambda v: v.line_start)
        
        return file_groups