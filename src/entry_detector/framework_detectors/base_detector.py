"""
Base Framework Detector

Abstract base class for all framework-specific detectors.
Provides common functionality and enforces consistent interface.
"""

import re
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Pattern, Any
import logging

from ..models import (
    EntryPoint, EntryPointCandidate, EntryPointType, 
    InputSource, InputSourceType, RouteInfo, SecurityFeature
)
from cli_navigator.navigator import FileInfo

logger = logging.getLogger(__name__)


class BaseFrameworkDetector(ABC):
    """
    Abstract base class for all framework detectors
    
    Provides common functionality for:
    - Pattern loading and compilation
    - File content reading
    - Basic code analysis
    - Security feature detection
    """
    
    def __init__(self, framework_name: str):
        self.framework_name = framework_name
        self.patterns: Dict[str, List[Pattern]] = {}
        self.config: Dict[str, Any] = {}
        self._compiled_patterns_cache: Dict[str, Pattern] = {}
        
        # Load framework-specific patterns
        self._load_patterns()
    
    @abstractmethod
    def detect_framework(self, file_info: FileInfo) -> bool:
        """
        Detect if this file belongs to this framework
        
        Args:
            file_info: File information from CLI Navigator
            
        Returns:
            True if framework is detected, False otherwise
        """
        pass
    
    @abstractmethod
    def find_entry_points(self, file_info: FileInfo) -> List[EntryPointCandidate]:
        """
        Find potential entry points in this file
        
        Args:
            file_info: File information from CLI Navigator
            
        Returns:
            List of entry point candidates
        """
        pass
    
    @abstractmethod
    def analyze_entry_point(self, candidate: EntryPointCandidate, file_content: str) -> EntryPoint:
        """
        Perform deep analysis of a specific entry point
        
        Args:
            candidate: Entry point candidate to analyze
            file_content: Full content of the source file
            
        Returns:
            Complete EntryPoint object with analysis results
        """
        pass
    
    def _load_patterns(self):
        """Load and compile regex patterns for this framework"""
        try:
            pattern_file = self._get_pattern_file_path()
            if pattern_file.exists():
                with open(pattern_file, 'r') as f:
                    pattern_data = json.load(f)
                
                # Compile regex patterns
                for category, pattern_list in pattern_data.get('patterns', {}).items():
                    self.patterns[category] = []
                    for pattern_info in pattern_list:
                        if isinstance(pattern_info, str):
                            # Simple string pattern
                            compiled = re.compile(pattern_info, re.MULTILINE | re.DOTALL)
                            self.patterns[category].append(compiled)
                        elif isinstance(pattern_info, dict):
                            # Pattern with metadata
                            pattern_str = pattern_info.get('pattern', '')
                            flags = self._parse_regex_flags(pattern_info.get('flags', []))
                            compiled = re.compile(pattern_str, flags)
                            setattr(compiled, 'metadata', pattern_info)  # Store metadata safely
                            self.patterns[category].append(compiled)
                
                # Load configuration
                self.config = pattern_data.get('config', {})
                
                logger.debug(f"Loaded {len(self.patterns)} pattern categories for {self.framework_name}")
            else:
                logger.warning(f"Pattern file not found: {pattern_file}")
                
        except Exception as e:
            logger.error(f"Error loading patterns for {self.framework_name}: {e}")
            self.patterns = {}
    
    def _get_pattern_file_path(self) -> Path:
        """Get the path to this framework's pattern file"""
        # Assuming we're in src/entry_detector/framework_detectors/
        project_root = Path(__file__).parent.parent.parent.parent
        return project_root / 'config' / 'entry_detection' / f'{self.framework_name}_patterns.json'
    
    def _parse_regex_flags(self, flag_names: List[str]) -> int:
        """Convert flag names to regex flag constants"""
        flag_map = {
            'MULTILINE': re.MULTILINE,
            'DOTALL': re.DOTALL,
            'IGNORECASE': re.IGNORECASE,
            'VERBOSE': re.VERBOSE
        }
        
        flags = 0
        for flag_name in flag_names:
            if flag_name in flag_map:
                flags |= flag_map[flag_name]
        
        return flags if flags else re.MULTILINE | re.DOTALL
    
    def read_file_content(self, file_path: Path) -> str:
        """
        Safely read file content with encoding detection
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            File content as string, empty string if error
        """
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 for problematic files
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                return ""
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return ""
    
    def find_pattern_matches(self, content: str, pattern_category: str) -> List[re.Match]:
        """
        Find all matches for a specific pattern category
        
        Args:
            content: File content to search
            pattern_category: Category of patterns to use
            
        Returns:
            List of regex match objects
        """
        matches = []
        
        if pattern_category in self.patterns:
            for pattern in self.patterns[pattern_category]:
                try:
                    pattern_matches = pattern.finditer(content)
                    matches.extend(pattern_matches)
                except Exception as e:
                    logger.error(f"Error matching pattern {pattern.pattern}: {e}")
        
        return matches
    
    def extract_function_info(self, content: str, function_name: str) -> Dict[str, Any]:
        """
        Extract detailed information about a specific function
        
        Args:
            content: File content
            function_name: Name of function to analyze
            
        Returns:
            Dictionary with function information
        """
        info = {
            'signature': '',
            'parameters': [],
            'decorators': [],
            'line_start': 0,
            'line_end': 0,
            'source_code': ''
        }
        
        lines = content.split('\n')
        
        # Find function definition
        for i, line in enumerate(lines):
            if f'def {function_name}(' in line or f'function {function_name}(' in line:
                info['line_start'] = i + 1
                info['signature'] = line.strip()
                
                # Look for decorators above the function
                j = i - 1
                while j >= 0 and (lines[j].strip().startswith('@') or lines[j].strip() == ''):
                    if lines[j].strip().startswith('@'):
                        info['decorators'].insert(0, lines[j].strip())
                    j -= 1
                
                # Extract function body (simplified - just get a few lines)
                body_lines = []
                j = i
                indent_level = len(line) - len(line.lstrip())
                
                while j < len(lines):
                    current_line = lines[j]
                    if j > i and current_line.strip() and len(current_line) - len(current_line.lstrip()) <= indent_level:
                        # Function ended
                        break
                    body_lines.append(current_line)
                    j += 1
                    if j - i > 20:  # Limit to first 20 lines of function
                        break
                
                info['line_end'] = j
                info['source_code'] = '\n'.join(body_lines)
                break
        
        # Extract parameters from signature
        if '(' in info['signature'] and ')' in info['signature']:
            param_str = info['signature'][info['signature'].find('(') + 1:info['signature'].rfind(')')]
            if param_str.strip():
                # Simple parameter extraction (doesn't handle complex cases)
                params = [p.strip().split('=')[0].strip() for p in param_str.split(',')]
                info['parameters'] = [p for p in params if p and p not in ['self', 'cls']]
        
        return info
    
    def detect_input_sources(self, content: str, function_name: str) -> List[InputSource]:
        """
        Detect external input sources in a function
        
        Args:
            content: File content
            function_name: Function to analyze
            
        Returns:
            List of detected input sources
        """
        input_sources = []
        lines = content.split('\n')
        
        # Common input source patterns
        input_patterns = {
            InputSourceType.HTTP_FORM_DATA: [
                r'request\.form\[(["\'])([^"\']+)\1\]',
                r'request\.form\.get\(["\']([^"\']+)["\']',
            ],
            InputSourceType.HTTP_QUERY_PARAM: [
                r'request\.args\[(["\'])([^"\']+)\1\]',
                r'request\.args\.get\(["\']([^"\']+)["\']',
                r'req\.query\.(\w+)',
            ],
            InputSourceType.HTTP_JSON_BODY: [
                r'request\.json\[(["\'])([^"\']+)\1\]',
                r'request\.json\.get\(["\']([^"\']+)["\']',
                r'req\.body\.(\w+)',
            ],
            InputSourceType.COMMAND_LINE_ARGS: [
                r'sys\.argv\[(\d+)\]',
                r'args\.(\w+)',
                r'parser\.parse_args\(\)',
            ],
            InputSourceType.ENVIRONMENT_VARS: [
                r'os\.environ\[(["\'])([^"\']+)\1\]',
                r'os\.environ\.get\(["\']([^"\']+)["\']',
                r'process\.env\.(\w+)',
            ]
        }
        
        # Find function boundaries
        func_start = func_end = 0
        for i, line in enumerate(lines):
            if f'def {function_name}(' in line or f'function {function_name}(' in line:
                func_start = i
                # Find function end (simplified)
                indent = len(line) - len(line.lstrip())
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) <= indent:
                        func_end = j
                        break
                else:
                    func_end = len(lines)
                break
        
        # Search for input patterns within function
        for line_num in range(func_start, func_end):
            line = lines[line_num]
            
            for source_type, patterns in input_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        var_name = match.group(2) if match.lastindex >= 2 else match.group(1)
                        
                        input_source = InputSource(
                            source_type=source_type,
                            variable_name=var_name,
                            line_number=line_num + 1,
                            raw_code=line.strip()
                        )
                        input_sources.append(input_source)
        
        return input_sources
    
    def detect_security_features(self, content: str, function_name: str) -> List[SecurityFeature]:
        """
        Detect security features and protections in a function
        
        Args:
            content: File content
            function_name: Function to analyze
            
        Returns:
            List of detected security features
        """
        security_features = []
        
        # Security feature patterns
        security_patterns = {
            'authentication': [
                r'@login_required',
                r'@requires_auth',
                r'authenticate\(',
                r'check_auth\(',
                r'verify_token\(',
            ],
            'input_validation': [
                r'validate\(',
                r'sanitize\(',
                r'escape\(',
                r'clean\(',
                r'validator\.',
            ],
            'csrf_protection': [
                r'@csrf_protect',
                r'csrf_token',
                r'CSRFProtect',
                r'csrf\.protect',
            ],
            'output_encoding': [
                r'escape\(',
                r'html\.escape',
                r'markupsafe',
                r'sanitize_html',
            ]
        }
        
        # Get function content
        func_info = self.extract_function_info(content, function_name)
        func_content = func_info['source_code']
        decorators = func_info['decorators']
        
        # Check decorators and function content
        all_content = '\n'.join(decorators) + '\n' + func_content
        
        for feature_type, patterns in security_patterns.items():
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
    
    def detect_database_access(self, content: str, function_name: str) -> bool:
        """
        Detect if function accesses databases
        
        Args:
            content: File content
            function_name: Function to analyze
            
        Returns:
            True if database access detected
        """
        func_info = self.extract_function_info(content, function_name)
        func_content = func_info['source_code']
        
        db_patterns = [
            r'\.execute\(',
            r'\.query\(',
            r'SELECT\s+',
            r'INSERT\s+',
            r'UPDATE\s+',
            r'DELETE\s+',
            r'db\.',
            r'cursor\.',
            r'session\.',
            r'Model\.',
            r'\.save\(',
            r'\.create\(',
            r'\.filter\(',
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    def detect_file_system_access(self, content: str, function_name: str) -> bool:
        """
        Detect if function accesses file system
        
        Args:
            content: File content
            function_name: Function to analyze
            
        Returns:
            True if file system access detected
        """
        func_info = self.extract_function_info(content, function_name)
        func_content = func_info['source_code']
        
        fs_patterns = [
            r'open\(',
            r'with\s+open',
            r'\.read\(',
            r'\.write\(',
            r'\.readlines\(',
            r'fs\.',
            r'path\.',
            r'os\.path',
            r'pathlib',
        ]
        
        for pattern in fs_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    def detect_system_command_execution(self, content: str, function_name: str) -> bool:
        """
        Detect if function executes system commands
        
        Args:
            content: File content
            function_name: Function to analyze
            
        Returns:
            True if system command execution detected
        """
        func_info = self.extract_function_info(content, function_name)
        func_content = func_info['source_code']
        
        cmd_patterns = [
            r'subprocess\.',
            r'os\.system\(',
            r'os\.popen\(',
            r'exec\(',
            r'eval\(',
            r'shell=True',
            r'cmd\.',
            r'spawn\(',
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, func_content, re.IGNORECASE):
                return True
        
        return False
    
    def get_context_lines(self, content: str, line_number: int, context_size: int = 3) -> List[str]:
        """
        Get context lines around a specific line number
        
        Args:
            content: File content
            line_number: Target line number (1-based)
            context_size: Number of lines before and after
            
        Returns:
            List of context lines
        """
        lines = content.split('\n')
        start = max(0, line_number - context_size - 1)
        end = min(len(lines), line_number + context_size)
        
        context = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == line_number else "    "
            context.append(f"{marker}{line_num:3d}: {lines[i]}")
        
        return context