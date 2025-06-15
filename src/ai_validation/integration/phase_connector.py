"""
Phase Connector - Bridges Phase 1/2 with Phase 3 AI validation.
File: src/ai_validation/integration/phase_connector.py
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

# Import Phase 1 models
import sys
from pathlib import Path
try:
    from entry_detector.models import EntryPoint
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from entry_detector.models import EntryPoint

# Import Phase 2 models  
try:
    from rag_system.models import FixSuggestion
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from rag_system.models import FixSuggestion

# Import Phase 3 models
from ..models.validation_models import VulnerabilityAnalysis, FixQualityAnalysis
from ..models.consensus_models import ConsensusResult


@dataclass
class ValidationRequest:
    """Request for AI validation of vulnerability and fix."""
    entry_point: EntryPoint
    fix_suggestion: FixSuggestion
    source_code: str
    project_context: Dict[str, Any]


@dataclass
class ValidationResult:
    """Complete AI validation result."""
    entry_point: EntryPoint
    fix_suggestion: FixSuggestion
    vulnerability_analysis: VulnerabilityAnalysis
    fix_quality_analysis: FixQualityAnalysis
    consensus_result: ConsensusResult
    overall_confidence: float
    recommendation: str


class PhaseConnector:
    """
    Connects Phase 1/2 outputs to Phase 3 AI validation.
    
    Responsibilities:
    - Convert Phase 1/2 data structures to Phase 3 formats
    - Coordinate vulnerability validation and fix quality analysis
    - Aggregate results into comprehensive assessments
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def create_validation_requests(self, 
                                 entry_points: List[EntryPoint],
                                 fix_suggestions: List[FixSuggestion],
                                 project_path: str) -> List[ValidationRequest]:
        """
        Create AI validation requests from Phase 1/2 outputs.
        
        Args:
            entry_points: Detected vulnerabilities from Phase 1
            fix_suggestions: Generated fixes from Phase 2
            project_path: Path to the project being analyzed
            
        Returns:
            List of validation requests for Phase 3
        """
        self.logger.info(f"Creating validation requests for {len(entry_points)} entry points")
        
        requests = []
        
        # Match entry points with their corresponding fixes
        for entry_point in entry_points:
            # Find matching fix suggestion
            matching_fix = self._find_matching_fix(entry_point, fix_suggestions)
            
            if matching_fix:
                # Load source code for the entry point
                source_code = self._load_source_code(entry_point.file_path, project_path)
                
                # Create project context
                project_context = self._create_project_context(entry_point, project_path)
                
                request = ValidationRequest(
                    entry_point=entry_point,
                    fix_suggestion=matching_fix,
                    source_code=source_code,
                    project_context=project_context
                )
                
                requests.append(request)
                self.logger.debug(f"Created validation request for {entry_point.function_name}")
            else:
                self.logger.warning(f"No matching fix found for entry point: {entry_point.function_name}")
        
        self.logger.info(f"Created {len(requests)} validation requests")
        return requests
    
    def _find_matching_fix(self, entry_point: EntryPoint, 
                          fix_suggestions: List[FixSuggestion]) -> Optional[FixSuggestion]:
        """Find fix suggestion that matches the entry point."""
        
        # Look for exact function match first
        for fix in fix_suggestions:
            if (hasattr(fix, 'function_name') and 
                fix.function_name == entry_point.function_name):
                return fix
        
        # Look for file and line number match
        for fix in fix_suggestions:
            if (hasattr(fix, 'file_path') and hasattr(fix, 'line_number') and
                fix.file_path == entry_point.file_path and
                fix.line_number >= entry_point.line_start and
                fix.line_number <= entry_point.line_end):
                return fix
        
        # Look for general file match (less precise)
        for fix in fix_suggestions:
            if (hasattr(fix, 'file_path') and 
                fix.file_path == entry_point.file_path):
                return fix
        
        return None
    
    def _load_source_code(self, file_path: str, project_path: str) -> str:
        """Load source code for the vulnerable file."""
        try:
            full_path = Path(project_path) / file_path
            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                self.logger.warning(f"Source file not found: {full_path}")
                return ""
        except Exception as e:
            self.logger.error(f"Error loading source code from {file_path}: {e}")
            return ""
    
    def _create_project_context(self, entry_point: EntryPoint, project_path: str) -> Dict[str, Any]:
        """Create project context for AI analysis."""
        
        context = {
            "project_path": project_path,
            "file_path": entry_point.file_path,
            "function_name": entry_point.function_name,
            "vulnerability_type": self._infer_vulnerability_type(entry_point),
            "risk_factors": entry_point.risk_factors,
            "business_impact": entry_point.business_impact,
            "framework": "Flask",  # Could be detected dynamically
        }
        
        # Add additional context based on entry point properties
        if hasattr(entry_point, 'input_sources'):
            context["input_sources"] = entry_point.input_sources
        
        if hasattr(entry_point, 'output_sinks'):
            context["output_sinks"] = entry_point.output_sinks
        
        return context
    
    def _infer_vulnerability_type(self, entry_point: EntryPoint) -> str:
        """Infer vulnerability type from entry point characteristics."""
        risk_factors = [f.lower() for f in entry_point.risk_factors]
        
        if any("sql" in f or "database" in f for f in risk_factors) or entry_point.database_access:
            return "SQL_INJECTION"
        elif any(f in ["html_output", "no_escaping", "user_input"] for f in risk_factors):
            return "XSS"
        elif entry_point.file_system_access:
            return "PATH_TRAVERSAL"
        elif entry_point.system_command_execution:
            return "COMMAND_INJECTION"
        else:
            return "SECURITY_VULNERABILITY"
    
    def aggregate_validation_results(self, 
                                   vulnerability_analysis: VulnerabilityAnalysis,
                                   fix_quality_analysis: FixQualityAnalysis,
                                   consensus_result: ConsensusResult,
                                   entry_point: EntryPoint,
                                   fix_suggestion: FixSuggestion) -> ValidationResult:
        """
        Aggregate individual validation results into comprehensive assessment.
        
        Args:
            vulnerability_analysis: AI analysis of vulnerability validity
            fix_quality_analysis: AI analysis of fix quality
            consensus_result: Multi-model consensus decision
            entry_point: Original vulnerability detection
            fix_suggestion: Generated fix suggestion
            
        Returns:
            Comprehensive validation result
        """
        # Calculate overall confidence as weighted average
        # Consensus gets highest weight, then vulnerability analysis, then fix quality
        overall_confidence = (
            consensus_result.consensus_confidence * 0.5 +      # 50%
            vulnerability_analysis.confidence_score * 0.3 +    # 30%
            fix_quality_analysis.analysis_confidence * 0.2     # 20%
        )
        
        # Generate recommendation based on all analyses
        recommendation = self._generate_recommendation(
            vulnerability_analysis, fix_quality_analysis, consensus_result, overall_confidence
        )
        
        return ValidationResult(
            entry_point=entry_point,
            fix_suggestion=fix_suggestion,
            vulnerability_analysis=vulnerability_analysis,
            fix_quality_analysis=fix_quality_analysis,
            consensus_result=consensus_result,
            overall_confidence=overall_confidence,
            recommendation=recommendation
        )
    
    def _generate_recommendation(self, 
                               vuln_analysis: VulnerabilityAnalysis,
                               fix_analysis: FixQualityAnalysis,
                               consensus: ConsensusResult,
                               overall_confidence: float) -> str:
        """Generate actionable recommendation based on all analyses."""
        
        recommendations = []
        
        # Vulnerability validity assessment
        if consensus.final_decision and vuln_analysis.is_genuine_vulnerability:
            if overall_confidence >= 0.8:
                recommendations.append("🔴 HIGH PRIORITY: Confirmed vulnerability with high confidence")
            elif overall_confidence >= 0.6:
                recommendations.append("🟡 MEDIUM PRIORITY: Likely vulnerability, review recommended")
            else:
                recommendations.append("🟡 LOW CONFIDENCE: Potential vulnerability, manual review required")
        else:
            if overall_confidence >= 0.7:
                recommendations.append("✅ FALSE POSITIVE: High confidence this is not a real vulnerability")
            else:
                recommendations.append("❓ UNCERTAIN: Mixed signals, manual security review recommended")
        
        # Fix quality assessment
        if fix_analysis.overall_quality_score >= 80:
            recommendations.append("✅ Fix quality is excellent, ready for implementation")
        elif fix_analysis.overall_quality_score >= 70:
            recommendations.append("⚠️ Fix quality is acceptable with minor improvements needed")
        elif fix_analysis.overall_quality_score >= 60:
            recommendations.append("⚠️ Fix quality needs improvement before implementation")
        else:
            recommendations.append("🔴 Fix quality is poor, requires significant revision")
        
        # Consensus considerations
        if consensus.uncertainty_flag:
            recommendations.append("❓ Models showed disagreement - expert review recommended")
        
        # Security-specific recommendations
        if vuln_analysis.is_genuine_vulnerability and fix_analysis.security_effectiveness_score < 80:
            recommendations.append("🔴 CRITICAL: Fix may not fully address security vulnerability")
        
        return " | ".join(recommendations)
    
    def create_validation_summary(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Create summary statistics for validation results."""
        
        if not results:
            return {"error": "No validation results to summarize"}
        
        total_vulns = len(results)
        confirmed_vulns = sum(1 for r in results if r.vulnerability_analysis.is_genuine_vulnerability)
        false_positives = total_vulns - confirmed_vulns
        
        high_confidence = sum(1 for r in results if r.overall_confidence >= 0.8)
        medium_confidence = sum(1 for r in results if 0.6 <= r.overall_confidence < 0.8)
        low_confidence = sum(1 for r in results if r.overall_confidence < 0.6)
        
        avg_fix_quality = sum(r.fix_quality_analysis.overall_quality_score for r in results) / total_vulns
        
        return {
            "total_analyzed": total_vulns,
            "confirmed_vulnerabilities": confirmed_vulns,
            "false_positives": false_positives,
            "confidence_distribution": {
                "high": high_confidence,
                "medium": medium_confidence,
                "low": low_confidence
            },
            "average_fix_quality_score": round(avg_fix_quality, 1),
            "recommendations_requiring_review": sum(1 for r in results if "manual review" in r.recommendation.lower()),
            "critical_issues": sum(1 for r in results if "CRITICAL" in r.recommendation),
        }