"""
Flask Framework Detector

Specialized detector for Flask web applications.
Identifies Flask routes, analyzes request handling, and assesses security risks.
"""

import re
from typing import List, Optional, Dict, Any
import logging

from .base_detector import BaseFrameworkDetector
from ..models import (
    EntryPoint, EntryPointCandidate, EntryPointType, RouteInfo,
    InputSource, InputSourceType, SecurityFeature, RiskLevel
)
from ...cli_navigator.navigator import FileInfo, FileType

logger = logging.getLogger(__name__)


class FlaskDetector(BaseFrameworkDetector):
    """
    Flask-specific entry point detector
    
    Detects:
    - Flask route handlers (@app.route, @bp.route)
    - Blueprint registrations
    - Before/after request handlers
    - Error handlers
    - API endpoints
    """
    
    def __init__(self):
        super().__init__('flask')
        
        # Flask-specific patterns (fallback if config file missing)
        self.default_patterns = {
            'route_decorators': [
                r'@app\.route\s*\(\s*[\'"]([^"\']+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?.*?\)',
                r'@bp\.route\s*\(\s*[\'"]([^"\']+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?.*?\)',
                r'@(\w+)\.route\s*\(\s*[\'"]([^"\']+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?.*?\)',
            ],
            'flask_imports': [
                r'from\s+flask\s+import',
                r'import\s+flask',
                r'Flask\s*\(',
            ],
            'blueprint_patterns': [
                r'Blueprint\s*\(',
                r'app\.register_blueprint\s*\(',
            ],
            'request_handlers': [
                r'@app\.before_request',
                r'@app\.after_request',
                r'@app\.teardown_request',
                r'@app\.errorhandler\s*\(\s*(\d+)\s*\)',
            ]
        }
    
    def detect_framework(self, file_info: FileInfo) -> bool:
        """
        Detect if this file is a Flask application
        
        Args:
            file_info: File information from CLI Navigator
            
        Returns:
            True if Flask framework detected
        """
        if file_info.file_type != FileType.PYTHON:
            return False
        
        content = self.read_file_content(file_info.path)
        if not content:
            return False
        
        # Check for Flask imports
        flask_indicators = [
            r'from\s+flask\s+import',
            r'import\s+flask',
            r'Flask\s*\(__name__\)',
            r'@app\.route',
            r'@bp\.route',
            r'Blueprint\s*\(',
        ]
        
        for pattern in flask_indicators:
            if re.search(pattern, content, re.MULTILINE):
                logger.debug(f"Flask detected in {file_info.path} via pattern: {pattern}")
                return True
        
        return False
    
    def find_entry_points(self, file_info: FileInfo) -> List[EntryPointCandidate]:
        """
        Find Flask entry points in the file
        
        Args:
            file_info: File information from CLI Navigator
            
        Returns:
            List of entry point candidates
        """
        if not self.detect_framework(file_info):
            return []
        
        content = self.read_file_content(file_info.path)
        if not content:
            return []
        
        candidates = []
        
        # Find route handlers
        candidates.extend(self._find_route_handlers(file_info, content))
        
        # Find request handlers (before_request, etc.)
        candidates.extend(self._find_request_handlers(file_info, content))
        
        # Find error handlers
        candidates.extend(self._find_error_handlers(file_info, content))
        
        logger.info(f"Found {len(candidates)} Flask entry point candidates in {file_info.path}")
        return candidates
    
    def _find_route_handlers(self, file_info: FileInfo, content: str) -> List[EntryPointCandidate]:
        """Find Flask route handlers (@app.route, @bp.route)"""
        candidates = []
        lines = content.split('\n')
        
        route_patterns = [
            r'@app\.route\s*\(\s*[\'"]([^"\']+)[\'"]',
            r'@bp\.route\s*\(\s*[\'"]([^"\']+)[\'"]',
            r'@(\w+)\.route\s*\(\s*[\'"]([^"\']+)[\'"]',
        ]
        
        for i, line in enumerate(lines):
            for pattern in route_patterns:
                match = re.search(pattern, line)
                if match:
                    # Look for the function definition following the decorator
                    function_name = self._find_function_after_decorator(lines, i)
                    if function_name:
                        candidate = EntryPointCandidate(
                            file_path=file_info.path,
                            function_name=function_name,
                            line_number=i + 1,
                            raw_pattern_match=line.strip(),
                            framework_hint='flask',
                            confidence=0.9
                        )
                        candidates.append(candidate)
                        
                        logger.debug(f"Found Flask route: {function_name} at line {i + 1}")
        
        return candidates
    
    def _find_request_handlers(self, file_info: FileInfo, content: str) -> List[EntryPointCandidate]:
        """Find before_request, after_request handlers"""
        candidates = []
        lines = content.split('\n')
        
        handler_patterns = [
            r'@app\.before_request',
            r'@app\.after_request',
            r'@app\.teardown_request',
            r'@bp\.before_request',
            r'@bp\.after_request',
        ]
        
        for i, line in enumerate(lines):
            for pattern in handler_patterns:
                if re.search(pattern, line):
                    function_name = self._find_function_after_decorator(lines, i)
                    if function_name:
                        candidate = EntryPointCandidate(
                            file_path=file_info.path,
                            function_name=function_name,
                            line_number=i + 1,
                            raw_pattern_match=line.strip(),
                            framework_hint='flask',
                            confidence=0.8
                        )
                        candidates.append(candidate)
        
        return candidates
    
    def _find_error_handlers(self, file_info: FileInfo, content: str) -> List[EntryPointCandidate]:
        """Find error handlers (@app.errorhandler)"""
        candidates = []
        lines = content.split('\n')
        
        error_pattern = r'@app\.errorhandler\s*\(\s*(\d+)\s*\)'
        
        for i, line in enumerate(lines):
            match = re.search(error_pattern, line)
            if match:
                function_name = self._find_function_after_decorator(lines, i)
                if function_name:
                    candidate = EntryPointCandidate(
                        file_path=file_info.path,
                        function_name=function_name,
                        line_number=i + 1,
                        raw_pattern_match=line.strip(),
                        framework_hint='flask',
                        confidence=0.7
                    )
                    candidates.append(candidate)
        
        return candidates
    
    def _find_function_after_decorator(self, lines: List[str], decorator_line: int) -> Optional[str]:
        """Find function name following a decorator"""
        for i in range(decorator_line + 1, min(len(lines), decorator_line + 5)):
            line = lines[i].strip()
            if line.startswith('def '):
                # Extract function name
                match = re.search(r'def\s+(\w+)\s*\(', line)
                if match:
                    return match.group(1)
        return None
    
    def analyze_entry_point(self, candidate: EntryPointCandidate, file_content: str) -> EntryPoint:
        """
        Perform deep analysis of a Flask entry point
        
        Args:
            candidate: Entry point candidate to analyze
            file_content: Full content of the source file
            
        Returns:
            Complete EntryPoint object with Flask-specific analysis
        """
        entry_point = candidate.to_entry_point()
        entry_point.framework = 'flask'
        
        # Extract function information
        func_info = self.extract_function_info(file_content, candidate.function_name)
        entry_point.function_signature = func_info['signature']
        entry_point.parameters = func_info['parameters']
        entry_point.decorators = func_info['decorators']
        entry_point.line_start = func_info['line_start']
        entry_point.line_end = func_info['line_end']
        entry_point.source_code = func_info['source_code']
        
        # Determine entry point type and extract route info
        entry_point.entry_type, entry_point.route_info = self._determine_entry_type(candidate, func_info)
        
        # Detect input sources
        entry_point.input_sources = self._detect_flask_input_sources(file_content, candidate.function_name)
        entry_point.external_input_count = len(entry_point.input_sources)
        
        # Detect security features
        entry_point.security_features = self._detect_flask_security_features(file_content, candidate.function_name)
        self._update_security_flags(entry_point)
        
        # Detect system access patterns
        entry_point.database_access = self.detect_database_access(file_content, candidate.function_name)
        entry_point.file_system_access = self.detect_file_system_access(file_content, candidate.function_name)
        entry_point.system_command_execution = self.detect_system_command_execution(file_content, candidate.function_name)
        
        # Detect business impact factors
        entry_point = self._detect_business_impact_factors(entry_point, file_content)
        
        # Get context lines
        entry_point.context_lines = self.get_context_lines(file_content, entry_point.line_start, 3)
        
        logger.debug(f"Analyzed Flask entry point: {entry_point.function_name}")
        return entry_point
    
    def _determine_entry_type(self, candidate: EntryPointCandidate, func_info: Dict[str, Any]) -> tuple:
        """Determine the specific type of Flask entry point"""
        decorators = func_info['decorators']
        
        route_info = None
        entry_type = EntryPointType.FLASK_ENDPOINT
        
        for decorator in decorators:
            if '@app.route' in decorator or '@bp.route' in decorator:
                # Extract route information
                route_match = re.search(r'[\'"]([^"\']+)[\'"]', decorator)
                if route_match:
                    url_pattern = route_match.group(1)
                    
                    # Extract HTTP methods
                    methods_match = re.search(r'methods\s*=\s*\[([^\]]+)\]', decorator)
                    if methods_match:
                        methods_str = methods_match.group(1)
                        http_methods = [m.strip().strip('\'"') for m in methods_str.split(',')]
                    else:
                        http_methods = ['GET']  # Default Flask method
                    
                    route_info = RouteInfo(
                        url_pattern=url_pattern,
                        http_methods=http_methods
                    )
                    
                    # Determine if it's an API endpoint
                    if '/api/' in url_pattern or url_pattern.startswith('/api'):
                        entry_type = EntryPointType.API_ENDPOINT
                    else:
                        entry_type = EntryPointType.FLASK_ENDPOINT
            
            elif '@app.before_request' in decorator or '@app.after_request' in decorator:
                entry_type = EntryPointType.WEB_MIDDLEWARE
            
            elif '@app.errorhandler' in decorator:
                entry_type = EntryPointType.WEB_MIDDLEWARE
        
        return entry_type, route_info
    
    def _detect_flask_input_sources(self, content: str, function_name: str) -> List[InputSource]:
        """Detect Flask-specific input sources"""
        input_sources = []
        func_info = self.extract_function_info(content, function_name)
        func_content = func_info['source_code']
        lines = func_content.split('\n')
        
        # Flask-specific input patterns
        flask_patterns = {
            InputSourceType.HTTP_FORM_DATA: [
                r'request\.form\[(["\'])([^"\']+)\1\]',
                r'request\.form\.get\(["\']([^"\']+)["\']',
                r'request\.values\[(["\'])([^"\']+)\1\]',
                r'request\.values\.get\(["\']([^"\']+)["\']',
            ],
            InputSourceType.HTTP_QUERY_PARAM: [
                r'request\.args\[(["\'])([^"\']+)\1\]',
                r'request\.args\.get\(["\']([^"\']+)["\']',
            ],
            InputSourceType.HTTP_JSON_BODY: [
                r'request\.json\[(["\'])([^"\']+)\1\]',
                r'request\.json\.get\(["\']([^"\']+)["\']',
                r'request\.get_json\(\)',
            ],
            InputSourceType.HTTP_HEADERS: [
                r'request\.headers\[(["\'])([^"\']+)\1\]',
                r'request\.headers\.get\(["\']([^"\']+)["\']',
            ],
            InputSourceType.HTTP_COOKIES: [
                r'request\.cookies\[(["\'])([^"\']+)\1\]',
                r'request\.cookies\.get\(["\']([^"\']+)["\']',
            ],
            InputSourceType.FILE_UPLOAD: [
                r'request\.files\[(["\'])([^"\']+)\1\]',
                r'request\.files\.get\(["\']([^"\']+)["\']',
            ]
        }
        
        for line_num, line in enumerate(lines):
            for source_type, patterns in flask_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Extract variable name
                        if match.lastindex >= 2:
                            var_name = match.group(2)
                        elif 'get_json' in match.group(0):
                            var_name = 'json_body'
                        else:
                            var_name = match.group(1) if match.lastindex >= 1 else 'unknown'
                        
                        input_source = InputSource(
                            source_type=source_type,
                            variable_name=var_name,
                            line_number=func_info['line_start'] + line_num,
                            raw_code=line.strip()
                        )
                        
                        # Check for validation/sanitization
                        input_source.validation_present = self._check_input_validation(line)
                        input_source.sanitization_present = self._check_input_sanitization(line)
                        
                        input_sources.append(input_source)
        
        return input_sources
    
    def _detect_flask_security_features(self, content: str, function_name: str) -> List[SecurityFeature]:
        """Detect Flask-specific security features"""
        security_features = []
        func_info = self.extract_function_info(content, function_name)
        
        # Check decorators and function content
        all_content = '\n'.join(func_info['decorators']) + '\n' + func_info['source_code']
        
        # Flask-specific security patterns
        flask_security_patterns = {
            'authentication': [
                r'@login_required',
                r'@requires_auth',
                r'@jwt_required',
                r'current_user',
                r'session\[.+user',
                r'authenticate\(',
            ],
            'csrf_protection': [
                r'@csrf\.exempt',
                r'csrf_token',
                r'CSRFProtect',
                r'generate_csrf',
                r'validate_csrf',
            ],
            'input_validation': [
                r'wtforms',
                r'Form\(',
                r'validate\(',
                r'validator\.',
                r'marshmallow',
                r'schema\.load',
            ],
            'output_encoding': [
                r'escape\(',
                r'Markup\(',
                r'markupsafe',
                r'\|safe',
                r'autoescape',
            ],
            'rate_limiting': [
                r'@limiter',
                r'rate_limit',
                r'flask_limiter',
            ]
        }
        
        for feature_type, patterns in flask_security_patterns.items():
            found = False
            implementation_details = []
            
            for pattern in patterns:
                matches = re.finditer(pattern, all_content, re.IGNORECASE)
                for match in matches:
                    found = True
                    implementation_details.append(match.group(0))
            
            security_feature = SecurityFeature(
                feature_type=feature_type,
                is_present=found,
                implementation_details=', '.join(set(implementation_details))
            )
            security_features.append(security_feature)
        
        return security_features
    
    def _update_security_flags(self, entry_point: EntryPoint):
        """Update security boolean flags based on detected features"""
        for feature in entry_point.security_features:
            if feature.feature_type == 'authentication' and feature.is_present:
                entry_point.authentication_required = True
            elif feature.feature_type == 'input_validation' and feature.is_present:
                entry_point.input_validation_present = True
            elif feature.feature_type == 'output_encoding' and feature.is_present:
                entry_point.output_encoding_present = True
            elif feature.feature_type == 'csrf_protection' and feature.is_present:
                entry_point.csrf_protection = True
    
    def _detect_business_impact_factors(self, entry_point: EntryPoint, content: str) -> EntryPoint:
        """Detect factors that indicate business impact level"""
        func_content = entry_point.source_code
        
        # Admin/privileged access indicators
        admin_patterns = [
            r'/admin',
            r'admin_required',
            r'superuser',
            r'is_admin',
            r'role.*admin',
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                entry_point.has_admin_privileges = True
                break
        
        # Payment data handling
        payment_patterns = [
            r'payment',
            r'credit_card',
            r'stripe',
            r'paypal',
            r'billing',
            r'invoice',
            r'transaction',
        ]
        
        for pattern in payment_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                entry_point.handles_payment_data = True
                break
        
        # User data access patterns
        user_data_patterns = [
            r'User\.',
            r'\.users\.',
            r'user_id',
            r'profile',
            r'personal',
            r'email',
            r'phone',
        ]
        
        for pattern in user_data_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                entry_point.accesses_user_data = True
                break
        
        # System configuration access
        config_patterns = [
            r'config\.',
            r'settings\.',
            r'environment',
            r'env\.',
            r'SECRET_KEY',
            r'DATABASE_URL',
        ]
        
        for pattern in config_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                entry_point.can_modify_system_config = True
                break
        
        return entry_point
    
    def _check_input_validation(self, line: str) -> bool:
        """Check if input validation is present on this line"""
        validation_indicators = [
            'validate',
            'clean',
            'sanitize',
            'filter',
            'check',
            'verify',
        ]
        
        return any(indicator in line.lower() for indicator in validation_indicators)
    
    def _check_input_sanitization(self, line: str) -> bool:
        """Check if input sanitization is present on this line"""
        sanitization_indicators = [
            'escape',
            'sanitize',
            'clean',
            'strip',
            'replace',
        ]
        
        return any(indicator in line.lower() for indicator in sanitization_indicators)