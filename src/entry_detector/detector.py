"""
Entry Point Detector - Main Orchestrator

Coordinates all entry point detection activities:
- Framework detection and analysis
- Risk assessment using business impact model
- Entry point classification and ranking
"""

import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

from .models import (
    EntryPoint, EntryPointCandidate, EntryPointReport, 
    RiskLevel, EntryPointType
)
from .risk_assessor import RiskAssessor
from .framework_detectors.flask_detector import FlaskDetector
from cli_navigator.navigator import ScanResult, FileInfo, FileType

logger = logging.getLogger(__name__)


class EntryPointDetector:
    """
    Main entry point detection and analysis engine
    
    Orchestrates the complete analysis pipeline:
    1. Framework detection across multiple files
    2. Entry point discovery using framework-specific patterns
    3. Deep analysis of each entry point
    4. Business impact risk assessment
    5. Report generation with prioritized findings
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the entry point detector
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Initialize framework detectors
        self.framework_detectors = {
            'flask': FlaskDetector(),
            # TODO: Add other framework detectors in future phases
            # 'nextjs': NextJSDetector(),
            # 'vue': VueDetector(),
            # 'express': ExpressDetector(),
            # 'svelte': SvelteDetector(),
            # 'nodejs': NodeJSDetector()
        }
        
        # Initialize risk assessor
        self.risk_assessor = RiskAssessor()
        
        # Statistics tracking
        self.stats = {
            'files_analyzed': 0,
            'frameworks_detected': set(),
            'entry_points_found': 0,
            'high_risk_count': 0,
            'moderate_risk_count': 0,
            'low_risk_count': 0
        }
        
        logger.info("Entry Point Detector initialized with framework detectors: %s", 
                   list(self.framework_detectors.keys()))
    
    def analyze_entry_points(self, scan_result: ScanResult) -> EntryPointReport:
        """
        Main entry point for complete analysis
        
        Args:
            scan_result: Results from CLI Navigator scan
            
        Returns:
            Complete entry point analysis report
        """
        start_time = time.time()
        logger.info("Starting entry point analysis for %s", scan_result.target_directory)
        
        # Reset statistics
        self._reset_stats()
        
        # Step 1: Discover entry point candidates
        candidates = self._discover_candidates(scan_result)
        logger.info("Discovered %d entry point candidates", len(candidates))
        
        # Step 2: Analyze each candidate
        entry_points = self._analyze_candidates(candidates)
        logger.info("Analyzed %d entry points", len(entry_points))
        
        # Step 3: Assess risks using business impact model
        assessed_entry_points = self._assess_risks(entry_points)
        logger.info("Completed risk assessment")
        
        # Step 4: Generate comprehensive report
        report = self._generate_report(scan_result, assessed_entry_points, time.time() - start_time)
        
        logger.info("Entry point analysis completed in %.2f seconds", report.scan_duration)
        return report
    
    def _reset_stats(self):
        """Reset internal statistics"""
        self.stats = {
            'files_analyzed': 0,
            'frameworks_detected': set(),
            'entry_points_found': 0,
            'high_risk_count': 0,
            'moderate_risk_count': 0,
            'low_risk_count': 0
        }
    
    def _discover_candidates(self, scan_result: ScanResult) -> List[EntryPointCandidate]:
        """
        Discover entry point candidates across all files
        
        Args:
            scan_result: CLI Navigator scan results
            
        Returns:
            List of entry point candidates
        """
        candidates = []
        
        # Focus on code files that could contain entry points
        analyzable_types = [FileType.PYTHON, FileType.JAVASCRIPT, FileType.TYPESCRIPT]
        
        for file_type in analyzable_types:
            if file_type in scan_result.files_by_type:
                for file_info in scan_result.files_by_type[file_type]:
                    file_candidates = self._analyze_file_for_entry_points(file_info)
                    candidates.extend(file_candidates)
                    self.stats['files_analyzed'] += 1
        
        # Also check CLI Navigator's initial entry point candidates
        initial_candidates = self._convert_cli_navigator_candidates(scan_result)
        candidates.extend(initial_candidates)
        
        # Remove duplicates
        candidates = self._deduplicate_candidates(candidates)
        
        return candidates
    
    def _analyze_file_for_entry_points(self, file_info: FileInfo) -> List[EntryPointCandidate]:
        """
        Analyze a single file for entry points using all framework detectors
        
        Args:
            file_info: File information from CLI Navigator
            
        Returns:
            List of entry point candidates found in this file
        """
        candidates = []
        
        try:
            # Try each framework detector
            for framework_name, detector in self.framework_detectors.items():
                if detector.detect_framework(file_info):
                    logger.debug(f"Framework {framework_name} detected in {file_info.path}")
                    self.stats['frameworks_detected'].add(framework_name)
                    
                    # Find entry points using this framework detector
                    framework_candidates = detector.find_entry_points(file_info)
                    candidates.extend(framework_candidates)
                    
                    # Only use the first matching framework to avoid duplicates
                    break
                    
        except Exception as e:
            logger.error(f"Error analyzing file {file_info.path}: {e}")
        
        return candidates
    
    def _convert_cli_navigator_candidates(self, scan_result: ScanResult) -> List[EntryPointCandidate]:
        """
        Convert CLI Navigator's entry point candidates to our format
        
        Args:
            scan_result: CLI Navigator scan results
            
        Returns:
            List of converted entry point candidates
        """
        candidates = []
        
        # Get files that CLI Navigator marked as entry point candidates
        for file_type, files in scan_result.files_by_type.items():
            for file_info in files:
                if file_info.is_entry_point_candidate:
                    # Create a generic candidate
                    candidate = EntryPointCandidate(
                        file_path=file_info.path,
                        function_name=self._extract_main_function_name(file_info),
                        line_number=1,  # Default to first line
                        raw_pattern_match=f"CLI Navigator identified: {file_info.path.name}",
                        framework_hint=None,
                        confidence=0.6  # Medium confidence for CLI-detected candidates
                    )
                    candidates.append(candidate)
        
        return candidates
    
    def _extract_main_function_name(self, file_info: FileInfo) -> str:
        """
        Extract the likely main function name from a file
        
        Args:
            file_info: File information
            
        Returns:
            Likely main function name
        """
        filename = file_info.path.stem
        
        # Common main function patterns
        if file_info.file_type == FileType.PYTHON:
            return 'main'  # Most Python entry points have main()
        elif file_info.file_type in [FileType.JAVASCRIPT, FileType.TYPESCRIPT]:
            return 'main'  # Or could be 'start', 'init'
        else:
            return filename  # Fallback to filename
    
    def _deduplicate_candidates(self, candidates: List[EntryPointCandidate]) -> List[EntryPointCandidate]:
        """
        Remove duplicate candidates based on file path and function name
        
        Args:
            candidates: List of candidates potentially with duplicates
            
        Returns:
            Deduplicated list of candidates
        """
        seen = set()
        unique_candidates = []
        
        for candidate in candidates:
            key = (candidate.file_path, candidate.function_name)
            if key not in seen:
                seen.add(key)
                unique_candidates.append(candidate)
            else:
                logger.debug(f"Duplicate candidate removed: {candidate.function_name} in {candidate.file_path}")
        
        return unique_candidates
    
    def _analyze_candidates(self, candidates: List[EntryPointCandidate]) -> List[EntryPoint]:
        """
        Perform deep analysis of entry point candidates
        
        Args:
            candidates: List of entry point candidates
            
        Returns:
            List of fully analyzed entry points
        """
        entry_points = []
        
        for candidate in candidates:
            try:
                entry_point = self._analyze_single_candidate(candidate)
                if entry_point:
                    entry_points.append(entry_point)
                    self.stats['entry_points_found'] += 1
                    
            except Exception as e:
                logger.error(f"Error analyzing candidate {candidate.function_name} in {candidate.file_path}: {e}")
        
        return entry_points
    
    def _analyze_single_candidate(self, candidate: EntryPointCandidate) -> Optional[EntryPoint]:
        """
        Analyze a single entry point candidate
        
        Args:
            candidate: Entry point candidate to analyze
            
        Returns:
            Analyzed EntryPoint or None if analysis fails
        """
        # Determine which framework detector to use
        framework = candidate.framework_hint
        
        if framework and framework in self.framework_detectors:
            detector = self.framework_detectors[framework]
        else:
            # Try to auto-detect framework
            detector = self._auto_detect_framework(candidate)
            if not detector:
                # Create a generic entry point
                return self._create_generic_entry_point(candidate)
        
        # Read file content
        try:
            with open(candidate.file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except Exception as e:
            logger.error(f"Error reading file {candidate.file_path}: {e}")
            return None
        
        # Use framework-specific analysis
        entry_point = detector.analyze_entry_point(candidate, file_content)
        
        logger.debug(f"Analyzed entry point: {entry_point.function_name} "
                    f"({entry_point.framework}, {entry_point.entry_type.value})")
        
        return entry_point
    
    def _auto_detect_framework(self, candidate: EntryPointCandidate) -> Optional[Any]:
        """
        Auto-detect framework for a candidate
        
        Args:
            candidate: Entry point candidate
            
        Returns:
            Framework detector or None
        """
        # Create a minimal FileInfo for framework detection
        file_info = FileInfo(
            path=candidate.file_path,
            size=0,  # Not needed for detection
            modified_time=0,  # Not needed for detection
            file_type=self._guess_file_type(candidate.file_path)
        )
        
        # Try each detector
        for framework_name, detector in self.framework_detectors.items():
            if detector.detect_framework(file_info):
                logger.debug(f"Auto-detected framework {framework_name} for {candidate.file_path}")
                return detector
        
        return None
    
    def _guess_file_type(self, file_path: Path) -> FileType:
        """Guess file type from extension"""
        extension = file_path.suffix.lower()
        
        if extension == '.py':
            return FileType.PYTHON
        elif extension in ['.js', '.jsx']:
            return FileType.JAVASCRIPT
        elif extension in ['.ts', '.tsx']:
            return FileType.TYPESCRIPT
        else:
            return FileType.UNKNOWN
    
    def _create_generic_entry_point(self, candidate: EntryPointCandidate) -> EntryPoint:
        """
        Create a generic entry point when framework-specific analysis isn't available
        
        Args:
            candidate: Entry point candidate
            
        Returns:
            Generic EntryPoint
        """
        entry_point = candidate.to_entry_point()
        entry_point.entry_type = EntryPointType.POTENTIAL
        entry_point.confidence = 0.5  # Lower confidence for generic analysis
        
        # Try to read file for basic analysis
        try:
            with open(candidate.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Basic pattern matching for common entry point indicators
            if 'if __name__ == "__main__"' in content:
                entry_point.entry_type = EntryPointType.CLI_MAIN
                entry_point.confidence = 0.8
            elif 'def main(' in content:
                entry_point.entry_type = EntryPointType.CLI_MAIN
                entry_point.confidence = 0.7
                
        except Exception as e:
            logger.warning(f"Could not read file {candidate.file_path} for generic analysis: {e}")
        
        return entry_point
    
    def _assess_risks(self, entry_points: List[EntryPoint]) -> List[EntryPoint]:
        """
        Assess business impact risks for all entry points
        
        Args:
            entry_points: List of entry points to assess
            
        Returns:
            List of entry points with risk assessments
        """
        assessed_entry_points = self.risk_assessor.assess_multiple_entry_points(entry_points)
        
        # Update statistics
        for ep in assessed_entry_points:
            if ep.risk_level == RiskLevel.HIGH:
                self.stats['high_risk_count'] += 1
            elif ep.risk_level == RiskLevel.MODERATE:
                self.stats['moderate_risk_count'] += 1
            else:
                self.stats['low_risk_count'] += 1
        
        return assessed_entry_points
    
    def _generate_report(self, scan_result: ScanResult, entry_points: List[EntryPoint], 
                        scan_duration: float) -> EntryPointReport:
        """
        Generate comprehensive entry point analysis report
        
        Args:
            scan_result: Original CLI Navigator scan results
            entry_points: Analyzed entry points with risk assessments
            scan_duration: Time taken for analysis
            
        Returns:
            Complete EntryPointReport
        """
        # Categorize entry points
        by_risk_level = {
            RiskLevel.HIGH: [ep for ep in entry_points if ep.risk_level == RiskLevel.HIGH],
            RiskLevel.MODERATE: [ep for ep in entry_points if ep.risk_level == RiskLevel.MODERATE],
            RiskLevel.LOW: [ep for ep in entry_points if ep.risk_level == RiskLevel.LOW]
        }
        
        by_framework = {}
        for ep in entry_points:
            if ep.framework:
                if ep.framework not in by_framework:
                    by_framework[ep.framework] = []
                by_framework[ep.framework].append(ep)
        
        by_entry_type = {}
        for ep in entry_points:
            if ep.entry_type not in by_entry_type:
                by_entry_type[ep.entry_type] = []
            by_entry_type[ep.entry_type].append(ep)
        
        # Create report
        report = EntryPointReport(
            scan_timestamp=datetime.now(),
            target_directory=scan_result.target_directory,
            total_entry_points=len(entry_points),
            by_risk_level=by_risk_level,
            by_framework=by_framework,
            by_entry_type=by_entry_type,
            all_entry_points=entry_points,
            high_risk_count=len(by_risk_level[RiskLevel.HIGH]),
            moderate_risk_count=len(by_risk_level[RiskLevel.MODERATE]),
            low_risk_count=len(by_risk_level[RiskLevel.LOW]),
            frameworks_detected=list(self.stats['frameworks_detected']),
            scan_duration=scan_duration
        )
        
        logger.info("Generated entry point report: %d total, %d high risk, %d moderate risk, %d low risk",
                   report.total_entry_points, report.high_risk_count, 
                   report.moderate_risk_count, report.low_risk_count)
        
        return report
    
    def get_high_risk_entry_points(self, entry_points: List[EntryPoint]) -> List[EntryPoint]:
        """
        Get only high-risk entry points sorted by risk score
        
        Args:
            entry_points: List of entry points
            
        Returns:
            List of high-risk entry points sorted by score (highest first)
        """
        high_risk = [ep for ep in entry_points if ep.risk_level == RiskLevel.HIGH]
        return sorted(high_risk, key=lambda ep: ep.risk_score, reverse=True)
    
    def get_entry_points_by_framework(self, entry_points: List[EntryPoint], 
                                     framework: str) -> List[EntryPoint]:
        """
        Get entry points for a specific framework
        
        Args:
            entry_points: List of entry points
            framework: Framework name (e.g., 'flask')
            
        Returns:
            List of entry points for the specified framework
        """
        return [ep for ep in entry_points if ep.framework == framework]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analysis statistics
        
        Returns:
            Dictionary with analysis statistics
        """
        return {
            'files_analyzed': self.stats['files_analyzed'],
            'frameworks_detected': list(self.stats['frameworks_detected']),
            'entry_points_found': self.stats['entry_points_found'],
            'risk_distribution': {
                'high': self.stats['high_risk_count'],
                'moderate': self.stats['moderate_risk_count'],
                'low': self.stats['low_risk_count']
            }
        }