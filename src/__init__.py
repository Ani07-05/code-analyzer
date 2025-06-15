"""
CLI Navigator Package

Provides filesystem navigation and file discovery functionality
for the Code Security Analyzer.
"""

from .cli_navigator.navigator import CLINavigator, FileInfo, FileType, ScanResult

__all__ = ['CLINavigator', 'FileInfo', 'FileType', 'ScanResult']
__version__ = '1.0.0'