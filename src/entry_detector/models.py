"""
Entry Point Detector Models - Core Data Structures
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime


class EntryPointType(Enum):
    """Classification of different entry point types"""
    WEB_SERVER = "web_server"
    WEB_ROUTE_HANDLER = "web_route"
    API_ENDPOINT = "api_endpoint"
    WEB_MIDDLEWARE = "web_middleware"
    CLI_MAIN = "cli_main"
    CLI_COMMAND = "cli_command"
    FLASK_ENDPOINT = "flask_endpoint"
    POTENTIAL = "potential"
    FALSE_POSITIVE = "false_positive"


class RiskLevel(Enum):
    """Business impact-based risk levels"""
    HIGH = "high"           # Business-ending damage
    MODERATE = "moderate"   # Individual user impact
    LOW = "low"            # Technical debt


class InputSourceType(Enum):
    """Types of external input sources"""
    HTTP_QUERY_PARAM = "http_query"
    HTTP_FORM_DATA = "http_form"
    HTTP_JSON_BODY = "http_json"
    HTTP_HEADERS = "http_headers"
    HTTP_COOKIES = "http_cookies"
    HTTP_PATH_PARAM = "http_path"
    FILE_UPLOAD = "file_upload"
    COMMAND_LINE_ARGS = "cli_args"
    ENVIRONMENT_VARS = "env_vars"


@dataclass
class InputSource:
    """Represents a source of external input to the application"""
    source_type: InputSourceType
    variable_name: str
    line_number: int
    raw_code: str
    validation_present: bool = False
    sanitization_present: bool = False


@dataclass
class SecurityFeature:
    """Represents a security feature or protection mechanism"""
    feature_type: str
    is_present: bool
    implementation_details: str = ""
    line_number: Optional[int] = None


@dataclass
class RouteInfo:
    """Information about web routes and endpoints"""
    url_pattern: str
    http_methods: List[str]
    parameters: List[str] = field(default_factory=list)
    middleware: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        methods = ",".join(self.http_methods)
        return f"{methods} {self.url_pattern}"


@dataclass
class EntryPoint:
    """Complete representation of an application entry point"""
    # Basic identification
    file_path: Path
    function_name: str
    class_name: Optional[str] = None
    line_start: int = 0
    line_end: int = 0
    
    # Classification
    entry_type: EntryPointType = EntryPointType.POTENTIAL
    framework: Optional[str] = None
    confidence: float = 0.0
    
    # Risk analysis
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    
    # Code analysis
    function_signature: str = ""
    parameters: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    
    # External input analysis
    input_sources: List[InputSource] = field(default_factory=list)
    external_input_count: int = 0
    
    # Security features
    security_features: List[SecurityFeature] = field(default_factory=list)
    authentication_required: bool = False
    input_validation_present: bool = False
    output_encoding_present: bool = False
    csrf_protection: bool = False
    
    # Database and system access
    database_access: bool = False
    file_system_access: bool = False
    system_command_execution: bool = False
    external_api_calls: bool = False
    
    # Business impact factors
    handles_payment_data: bool = False
    accesses_user_data: bool = False
    has_admin_privileges: bool = False
    can_modify_system_config: bool = False
    
    # Web-specific information
    route_info: Optional[RouteInfo] = None
    
    # Code context
    source_code: str = ""
    context_lines: List[str] = field(default_factory=list)
    
    def get_risk_summary(self) -> str:
        """Generate a human-readable risk summary"""
        
        summary = f"{self.risk_level.value.upper()} RISK (Score: {self.risk_score})\n"
        summary += f"Entry Point: {self.function_name} ({self.entry_type.value})\n"
        
        if self.route_info:
            summary += f"Route: {self.route_info}\n"
        
        if self.input_sources:
            summary += f"External Inputs: {len(self.input_sources)}\n"
        
        if self.risk_factors:
            summary += f"Risk Factors: {', '.join(self.risk_factors[:3])}\n"
        
        return summary
    
    def has_external_input(self) -> bool:
        """Check if this entry point processes external input"""
        return len(self.input_sources) > 0
    
    def is_web_endpoint(self) -> bool:
        """Check if this is a web-accessible endpoint"""
        web_types = {
            EntryPointType.WEB_ROUTE_HANDLER,
            EntryPointType.API_ENDPOINT,
            EntryPointType.FLASK_ENDPOINT,
        }
        return self.entry_type in web_types


@dataclass
class EntryPointCandidate:
    """Intermediate representation during entry point discovery"""
    file_path: Path
    function_name: str
    line_number: int
    raw_pattern_match: str
    framework_hint: Optional[str] = None
    confidence: float = 0.5
    
    def to_entry_point(self) -> EntryPoint:
        """Convert candidate to full EntryPoint for analysis"""
        return EntryPoint(
            file_path=self.file_path,
            function_name=self.function_name,
            line_start=self.line_number,
            confidence=self.confidence,
            framework=self.framework_hint
        )


@dataclass
class EntryPointReport:
    """Complete report of entry point analysis results"""
    scan_timestamp: datetime
    target_directory: Path
    total_entry_points: int
    
    # Categorized results
    by_risk_level: Dict[RiskLevel, List[EntryPoint]]
    by_framework: Dict[str, List[EntryPoint]]
    by_entry_type: Dict[EntryPointType, List[EntryPoint]]
    
    # All entry points
    all_entry_points: List[EntryPoint]
    
    # Summary statistics
    high_risk_count: int
    moderate_risk_count: int
    low_risk_count: int
    
    # Analysis metadata
    frameworks_detected: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    
    def __post_init__(self):
        """Calculate derived statistics"""
        self.high_risk_count = len(self.by_risk_level.get(RiskLevel.HIGH, []))
        self.moderate_risk_count = len(self.by_risk_level.get(RiskLevel.MODERATE, []))
        self.low_risk_count = len(self.by_risk_level.get(RiskLevel.LOW, []))
        
        self.frameworks_detected = list(set(
            ep.framework for ep in self.all_entry_points 
            if ep.framework
        ))
    
    def get_summary(self) -> str:
        """Generate human-readable summary"""
        return f"""
Entry Point Analysis Summary
============================
Directory: {self.target_directory}
Scan Duration: {self.scan_duration:.2f}s
Total Entry Points: {self.total_entry_points}

Risk Distribution:
  High Risk: {self.high_risk_count}
  Moderate Risk: {self.moderate_risk_count}  
  Low Risk: {self.low_risk_count}

Frameworks Detected: {', '.join(self.frameworks_detected)}
"""
    
    def get_attack_surface_score(self) -> float:
        """Calculate overall attack surface score (0.0-1.0, lower is better)"""
        if self.total_entry_points == 0:
            return 0.0
        
        total_risk = (
            self.high_risk_count * 0.8 +
            self.moderate_risk_count * 0.4 +
            self.low_risk_count * 0.1
        )
        
        return min(1.0, total_risk / self.total_entry_points)
