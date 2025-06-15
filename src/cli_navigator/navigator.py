"""
CLI Navigator Module - Core directory traversal and file discovery

This module handles all filesystem operations including:
- Directory validation and traversal
- File filtering and categorization
- Progress tracking and logging
- Permission handling and error recovery
"""

import os
import sys
import stat
import time
from pathlib import Path
from typing import List, Dict, Set, Optional, Generator, Tuple
from dataclasses import dataclass
from enum import Enum
import fnmatch
import logging

logger = logging.getLogger(__name__)


class FileType(Enum):
    """Enumeration of file types we care about for analysis"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    PHP = "php"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    """Container for file information and metadata"""
    path: Path
    size: int
    modified_time: float
    file_type: FileType
    is_entry_point_candidate: bool = False
    permissions: str = ""
    
    def __post_init__(self):
        """Calculate additional properties after initialization"""
        try:
            stat_info = self.path.stat()
            self.permissions = stat.filemode(stat_info.st_mode)
        except (OSError, PermissionError):
            self.permissions = "unknown"


@dataclass
class ScanResult:
    """Container for complete scan results"""
    target_directory: Path
    total_files: int
    analyzed_files: int
    skipped_files: int
    error_files: int
    files_by_type: Dict[FileType, List[FileInfo]]
    scan_duration: float
    errors: List[str]
    
    def get_summary(self) -> str:
        """Generate a human-readable summary of the scan"""
        return f"""
Scan Summary:
  Target: {self.target_directory}
  Duration: {self.scan_duration:.2f}s
  Total files found: {self.total_files}
  Analyzed: {self.analyzed_files}
  Skipped: {self.skipped_files}
  Errors: {self.error_files}
  
File types detected:
""" + "\n".join(f"  {ft.value}: {len(files)}" for ft, files in self.files_by_type.items() if files)


class CLINavigator:
    """
    Advanced filesystem navigator with intelligent filtering and analysis
    
    Features:
    - Recursive directory traversal with configurable depth
    - Smart file type detection
    - Performance optimization with progress tracking
    - Robust error handling and recovery
    - Configurable filtering rules
    """
    
    # File extension mappings
    EXTENSION_MAP = {
        '.py': FileType.PYTHON,
        '.pyw': FileType.PYTHON,
        '.js': FileType.JAVASCRIPT,
        '.jsx': FileType.JAVASCRIPT,
        '.mjs': FileType.JAVASCRIPT,
        '.ts': FileType.TYPESCRIPT,
        '.tsx': FileType.TYPESCRIPT,
        '.java': FileType.JAVA,
        '.cs': FileType.CSHARP,
        '.php': FileType.PHP,
        '.phtml': FileType.PHP,
        '.json': FileType.CONFIG,
        '.yaml': FileType.CONFIG,
        '.yml': FileType.CONFIG,
        '.toml': FileType.CONFIG,
        '.ini': FileType.CONFIG,
        '.cfg': FileType.CONFIG,
        '.conf': FileType.CONFIG,
        '.xml': FileType.CONFIG,
    }
    
    # Dependency file patterns
    DEPENDENCY_FILES = {
        'requirements.txt': FileType.DEPENDENCY,
        'pyproject.toml': FileType.DEPENDENCY,
        'setup.py': FileType.DEPENDENCY,
        'Pipfile': FileType.DEPENDENCY,
        'package.json': FileType.DEPENDENCY,
        'package-lock.json': FileType.DEPENDENCY,
        'yarn.lock': FileType.DEPENDENCY,
        'composer.json': FileType.DEPENDENCY,
        'composer.lock': FileType.DEPENDENCY,
        'pom.xml': FileType.DEPENDENCY,
        'build.gradle': FileType.DEPENDENCY,
        'packages.config': FileType.DEPENDENCY,
        '*.csproj': FileType.DEPENDENCY,
    }
    
    # Default exclusion patterns
    DEFAULT_EXCLUDED_DIRS = {
        '__pycache__', '.git', '.svn', '.hg', 'node_modules', 
        '.venv', 'venv', 'env', 'ENV', 'build', 'dist', 
        '.idea', '.vscode', 'target', 'bin', 'obj', 
        '.pytest_cache', '.coverage', 'htmlcov',
        '.mypy_cache', '.tox', '.cache'
    }
    
    DEFAULT_EXCLUDED_FILES = {
        '*.pyc', '*.pyo', '*.pyd', '*.so', '*.dll', '*.dylib',
        '*.exe', '*.o', '*.a', '*.lib', '*.class', '*.jar',
        '*.log', '*.tmp', '*.temp', '*.bak', '*.swp', '*.swo',
        '.DS_Store', 'Thumbs.db', '*.min.js', '*.min.css'
    }
    
    def __init__(self, 
                 max_file_size: int = 10 * 1024 * 1024,  # 10MB
                 max_depth: Optional[int] = None,
                 excluded_dirs: Optional[Set[str]] = None,
                 excluded_files: Optional[Set[str]] = None,
                 follow_symlinks: bool = False,
                 show_progress: bool = True):
        """
        Initialize the CLI Navigator
        
        Args:
            max_file_size: Maximum file size to analyze (bytes)
            max_depth: Maximum directory depth to traverse
            excluded_dirs: Additional directories to exclude
            excluded_files: Additional file patterns to exclude
            follow_symlinks: Whether to follow symbolic links
            show_progress: Whether to show progress during scanning
        """
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self.follow_symlinks = follow_symlinks
        self.show_progress = show_progress
        
        # Combine default and custom exclusions
        self.excluded_dirs = self.DEFAULT_EXCLUDED_DIRS.copy()
        if excluded_dirs:
            self.excluded_dirs.update(excluded_dirs)
            
        self.excluded_files = self.DEFAULT_EXCLUDED_FILES.copy()
        if excluded_files:
            self.excluded_files.update(excluded_files)
        
        # Initialize counters
        self.reset_counters()
    
    def reset_counters(self):
        """Reset internal counters for a new scan"""
        self.total_files = 0
        self.analyzed_files = 0
        self.skipped_files = 0
        self.error_files = 0
        self.errors = []
    
    def validate_directory(self, directory: str) -> Path:
        """
        Validate that the target directory exists and is accessible
        
        Args:
            directory: Path to the directory to validate
            
        Returns:
            Path object for the validated directory
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            PermissionError: If directory isn't readable
            NotADirectoryError: If path isn't a directory
        """
        path = Path(directory).resolve()
        
        if not path.exists():
            raise FileNotFoundError(f"Directory does not exist: {path}")
        
        if not path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path}")
        
        # Test readability
        try:
            list(path.iterdir())
        except PermissionError:
            raise PermissionError(f"Permission denied accessing directory: {path}")
        
        logger.info(f"Validated target directory: {path}")
        return path
    
    def _should_exclude_dir(self, dir_path: Path) -> bool:
        """Check if a directory should be excluded from scanning"""
        dir_name = dir_path.name
        
        # Check against excluded directory names
        if dir_name in self.excluded_dirs:
            return True
        
        # Check for hidden directories (starting with .)
        if dir_name.startswith('.') and dir_name not in {'.', '..'}:
            return True
        
        return False
    
    def _should_exclude_file(self, file_path: Path) -> bool:
        """Check if a file should be excluded from scanning"""
        file_name = file_path.name
        
        # Check against excluded file patterns
        for pattern in self.excluded_files:
            if fnmatch.fnmatch(file_name, pattern):
                return True
        
        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                return True
        except OSError:
            return True
        
        return False
    
    def _detect_file_type(self, file_path: Path) -> FileType:
        """
        Detect the type of a file based on extension and name
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileType enum value
        """
        file_name = file_path.name.lower()
        extension = file_path.suffix.lower()
        
        # Check dependency files first (by exact name)
        for dep_pattern, file_type in self.DEPENDENCY_FILES.items():
            if '*' in dep_pattern:
                if fnmatch.fnmatch(file_name, dep_pattern):
                    return file_type
            elif file_name == dep_pattern:
                return file_type
        
        # Check by extension
        return self.EXTENSION_MAP.get(extension, FileType.UNKNOWN)
    
    def _is_entry_point_candidate(self, file_path: Path, file_type: FileType) -> bool:
        """
        Determine if a file could be an application entry point
        
        Args:
            file_path: Path to the file
            file_type: Type of the file
            
        Returns:
            True if file could be an entry point
        """
        if file_type == FileType.UNKNOWN:
            return False
        
        file_name = file_path.name.lower()
        
        # Common entry point patterns
        entry_patterns = {
            'app.py', 'main.py', 'manage.py', 'wsgi.py', 'asgi.py',
            'app.js', 'index.js', 'server.js', 'main.js',
            'app.ts', 'index.ts', 'server.ts', 'main.ts',
            'index.php', 'app.php', 'bootstrap.php',
            'main.java', 'application.java', 'app.java',
            'program.cs', 'main.cs', 'application.cs'
        }
        
        return file_name in entry_patterns
    
    def _create_file_info(self, file_path: Path) -> Optional[FileInfo]:
        """
        Create FileInfo object for a file with error handling
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileInfo object or None if file can't be processed
        """
        try:
            stat_info = file_path.stat()
            file_type = self._detect_file_type(file_path)
            is_entry_candidate = self._is_entry_point_candidate(file_path, file_type)
            
            return FileInfo(
                path=file_path,
                size=stat_info.st_size,
                modified_time=stat_info.st_mtime,
                file_type=file_type,
                is_entry_point_candidate=is_entry_candidate
            )
        except (OSError, PermissionError) as e:
            self.errors.append(f"Error processing file {file_path}: {e}")
            self.error_files += 1
            return None
    
    def _traverse_directory(self, directory: Path, current_depth: int = 0) -> Generator[FileInfo, None, None]:
        """
        Recursively traverse directory and yield FileInfo objects
        
        Args:
            directory: Directory to traverse
            current_depth: Current traversal depth
            
        Yields:
            FileInfo objects for valid files
        """
        if self.max_depth is not None and current_depth > self.max_depth:
            return
        
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError) as e:
            self.errors.append(f"Error accessing directory {directory}: {e}")
            return
        
        # Sort entries for consistent processing order
        entries.sort(key=lambda p: (p.is_file(), p.name))
        
        for entry in entries:
            try:
                # Handle symbolic links
                if entry.is_symlink() and not self.follow_symlinks:
                    continue
                
                if entry.is_dir():
                    # Skip excluded directories
                    if self._should_exclude_dir(entry):
                        logger.debug(f"Excluding directory: {entry}")
                        continue
                    
                    # Recursively traverse subdirectory
                    yield from self._traverse_directory(entry, current_depth + 1)
                
                elif entry.is_file():
                    self.total_files += 1
                    
                    # Show progress
                    if self.show_progress and self.total_files % 100 == 0:
                        print(f"\rScanning... {self.total_files} files found", end="", file=sys.stderr)
                    
                    # Skip excluded files
                    if self._should_exclude_file(entry):
                        self.skipped_files += 1
                        continue
                    
                    # Create and yield FileInfo
                    file_info = self._create_file_info(entry)
                    if file_info:
                        self.analyzed_files += 1
                        yield file_info
                    
            except (PermissionError, OSError) as e:
                self.errors.append(f"Error processing {entry}: {e}")
                self.error_files += 1
    
    def scan_directory(self, directory: str) -> ScanResult:
        """
        Perform a complete scan of the specified directory
        
        Args:
            directory: Path to the directory to scan
            
        Returns:
            ScanResult object containing all scan information
        """
        start_time = time.time()
        self.reset_counters()
        
        # Validate directory
        target_path = self.validate_directory(directory)
        
        # Initialize result containers
        files_by_type: Dict[FileType, List[FileInfo]] = {
            file_type: [] for file_type in FileType
        }
        
        logger.info(f"Starting scan of: {target_path}")
        
        try:
            # Traverse directory and collect files
            for file_info in self._traverse_directory(target_path):
                files_by_type[file_info.file_type].append(file_info)
            
            if self.show_progress:
                print(f"\rScan complete! {self.total_files} files processed.", file=sys.stderr)
        
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            print("\nScan interrupted by user", file=sys.stderr)
        
        scan_duration = time.time() - start_time
        
        # Create and return scan result
        result = ScanResult(
            target_directory=target_path,
            total_files=self.total_files,
            analyzed_files=self.analyzed_files,
            skipped_files=self.skipped_files,
            error_files=self.error_files,
            files_by_type=files_by_type,
            scan_duration=scan_duration,
            errors=self.errors.copy()
        )
        
        logger.info(f"Scan completed in {scan_duration:.2f}s")
        return result
    
    def get_files_by_extension(self, scan_result: ScanResult, extensions: List[str]) -> List[FileInfo]:
        """
        Filter files by specific extensions from scan results
        
        Args:
            scan_result: Result from a previous scan
            extensions: List of extensions to filter (e.g., ['.py', '.js'])
            
        Returns:
            List of FileInfo objects matching the extensions
        """
        filtered_files = []
        for file_list in scan_result.files_by_type.values():
            for file_info in file_list:
                if file_info.path.suffix.lower() in extensions:
                    filtered_files.append(file_info)
        return filtered_files
    
    def get_entry_point_candidates(self, scan_result: ScanResult) -> List[FileInfo]:
        """
        Get all files that could be application entry points
        
        Args:
            scan_result: Result from a previous scan
            
        Returns:
            List of FileInfo objects that are entry point candidates
        """
        candidates = []
        for file_list in scan_result.files_by_type.values():
            for file_info in file_list:
                if file_info.is_entry_point_candidate:
                    candidates.append(file_info)
        return candidates