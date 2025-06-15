"""
Validation result data structures for Phase 3.
File: src/ai_validation/models/validation_models.py

Complete data models for AI validation results.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum


class ValidationStatus(Enum):
    """Validation result status."""
    GENUINE_VULNERABILITY = "genuine"
    FALSE_POSITIVE = "false_positive" 
    UNCERTAIN = "uncertain"
    ERROR = "error"


class ConfidenceLevel(Enum):
    """Confidence level categories."""
    VERY_HIGH = "very_high"    # 0.9+
    HIGH = "high"              # 0.7-0.9
    MEDIUM = "medium"          # 0.5-0.7
    LOW = "low"                # 0.3-0.5
    VERY_LOW = "very_low"      # <0.3


class BusinessImpact(Enum):
    """Business impact levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class ExploitabilityLevel(Enum):
    """Exploitability assessment levels."""
    HIGH = "high"      # Easy to exploit, common attack vectors
    MEDIUM = "medium"  # Moderate difficulty, some prerequisites
    LOW = "low"        # Difficult to exploit, many prerequisites
    NONE = "none"      # Not exploitable in practice


@dataclass
class VulnerabilityAnalysis:
    """
    Complete AI analysis of vulnerability genuineness.
    
    This is the main result from VulnerabilityVerifier containing
    all AI assessment data and confidence metrics.
    """
    
    # Core assessment
    is_genuine_vulnerability: bool
    confidence_score: float  # 0.0 to 1.0
    false_positive_probability: float  # 0.0 to 1.0
    
    # Detailed analysis
    code_context_analysis: str
    data_flow_analysis: str
    business_impact_assessment: str
    ai_reasoning: str
    evidence_citations: List[str]
    
    # Optional enhanced fields
    exploitability_level: Optional[str] = None
    attack_scenarios: Optional[List[str]] = None
    mitigating_factors: Optional[List[str]] = None
    framework_protections: Optional[List[str]] = None
    confidence_factors: Optional[Dict[str, float]] = None
    
    def __post_init__(self):
        """Validate and normalize data after initialization."""
        # Ensure confidence scores are in valid range
        self.confidence_score = max(0.0, min(1.0, self.confidence_score))
        self.false_positive_probability = max(0.0, min(1.0, self.false_positive_probability))
        
        # Initialize optional fields if None
        if self.attack_scenarios is None:
            self.attack_scenarios = []
        if self.mitigating_factors is None:
            self.mitigating_factors = []
        if self.framework_protections is None:
            self.framework_protections = []
        if self.confidence_factors is None:
            self.confidence_factors = {}
    
    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Get categorical confidence level."""
        if self.confidence_score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif self.confidence_score >= 0.7:
            return ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif self.confidence_score >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    @property
    def validation_status(self) -> ValidationStatus:
        """Get validation status based on analysis."""
        if self.confidence_score < 0.3:
            return ValidationStatus.UNCERTAIN
        elif self.is_genuine_vulnerability:
            return ValidationStatus.GENUINE_VULNERABILITY
        else:
            return ValidationStatus.FALSE_POSITIVE
    
    @property
    def business_impact_enum(self) -> BusinessImpact:
        """Get business impact as enum."""
        impact_str = self.business_impact_assessment.upper()
        if "CRITICAL" in impact_str:
            return BusinessImpact.CRITICAL
        elif "HIGH" in impact_str:
            return BusinessImpact.HIGH
        elif "MEDIUM" in impact_str:
            return BusinessImpact.MEDIUM
        elif "LOW" in impact_str:
            return BusinessImpact.LOW
        else:
            return BusinessImpact.NEGLIGIBLE
    
    @property
    def exploitability_enum(self) -> ExploitabilityLevel:
        """Get exploitability as enum."""
        if self.exploitability_level:
            level_str = self.exploitability_level.upper()
            if level_str == "HIGH":
                return ExploitabilityLevel.HIGH
            elif level_str == "MEDIUM":
                return ExploitabilityLevel.MEDIUM
            elif level_str == "LOW":
                return ExploitabilityLevel.LOW
            else:
                return ExploitabilityLevel.NONE
        return ExploitabilityLevel.MEDIUM  # Default
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of analysis for reporting."""
        return {
            "genuine_vulnerability": self.is_genuine_vulnerability,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "false_positive_probability": self.false_positive_probability,
            "business_impact": self.business_impact_enum.value,
            "exploitability": self.exploitability_enum.value,
            "evidence_count": len(self.evidence_citations),
            "mitigating_factors_count": len(self.mitigating_factors),
            "validation_status": self.validation_status.value
        }


@dataclass 
class FixQualityAnalysis:
    """
    AI analysis of fix suggestion quality and completeness.
    
    This will be the main result from FixQualityValidator.
    """
    
    # Overall quality metrics (required fields first)
    overall_quality_score: float  # 0.0 to 100.0
    completeness_score: float
    implementation_feasibility: float
    security_effectiveness: float
    code_maintainability: float
    performance_impact: float
    
    # Detailed analysis (required fields)
    improvement_suggestions: List[str]
    security_test_recommendations: List[str]
    implementation_guide: str
    potential_side_effects: List[str]
    
    # Quality factors (required fields)
    addresses_root_cause: bool
    handles_edge_cases: bool
    follows_best_practices: bool
    maintains_functionality: bool
    
    # AI reasoning (required fields)
    ai_reasoning: str
    confidence_score: float
    
    def __post_init__(self):
        """Validate quality scores."""
        # Ensure scores are in valid ranges
        self.overall_quality_score = max(0.0, min(100.0, self.overall_quality_score))
        self.completeness_score = max(0.0, min(100.0, self.completeness_score))
        self.implementation_feasibility = max(0.0, min(100.0, self.implementation_feasibility))
        self.security_effectiveness = max(0.0, min(100.0, self.security_effectiveness))
        self.code_maintainability = max(0.0, min(100.0, self.code_maintainability))
        self.performance_impact = max(0.0, min(100.0, self.performance_impact))
        self.confidence_score = max(0.0, min(1.0, self.confidence_score))
    
    @property
    def quality_grade(self) -> str:
        """Get letter grade for overall quality."""
        score = self.overall_quality_score
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 65:
            return "D+"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    @property
    def is_production_ready(self) -> bool:
        """Determine if fix is ready for production deployment."""
        return (self.overall_quality_score >= 75.0 and
                self.security_effectiveness >= 80.0 and
                self.implementation_feasibility >= 70.0 and
                self.confidence_score >= 0.7)
    
    @property
    def requires_review(self) -> bool:
        """Determine if fix requires human review before implementation."""
        return (self.overall_quality_score < 85.0 or
                len(self.potential_side_effects) > 2 or
                not self.addresses_root_cause or
                self.confidence_score < 0.8)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary for reporting."""
        return {
            "overall_quality_score": self.overall_quality_score,
            "quality_grade": self.quality_grade,
            "is_production_ready": self.is_production_ready,
            "requires_review": self.requires_review,
            "completeness_score": self.completeness_score,
            "security_effectiveness": self.security_effectiveness,
            "implementation_feasibility": self.implementation_feasibility,
            "confidence_score": self.confidence_score,
            "improvement_count": len(self.improvement_suggestions),
            "side_effects_count": len(self.potential_side_effects)
        }


@dataclass
class ConsensusResult:
    """
    Result of multi-model consensus analysis.
    
    Used when multiple AI models provide input on the same vulnerability.
    """
    
    # Final consensus decision (required fields first)
    final_decision: bool
    consensus_confidence: float
    agreement_percentage: float
    
    # Individual model results (required fields)
    model_votes: List[Dict[str, Any]]
    consensus_strategy_used: str
    
    # Disagreement analysis (required fields)
    has_significant_disagreement: bool
    consensus_reasoning: str
    evidence_weight: float
    
    # Optional fields with defaults
    disagreement_analysis: Optional[str] = None
    
    def __post_init__(self):
        """Validate consensus data."""
        self.consensus_confidence = max(0.0, min(1.0, self.consensus_confidence))
        self.agreement_percentage = max(0.0, min(100.0, self.agreement_percentage))
        self.evidence_weight = max(0.0, min(1.0, self.evidence_weight))
    
    @property
    def consensus_strength(self) -> str:
        """Get consensus strength description."""
        if self.agreement_percentage >= 90:
            return "Strong Consensus"
        elif self.agreement_percentage >= 75:
            return "Good Consensus"
        elif self.agreement_percentage >= 60:
            return "Moderate Consensus"
        else:
            return "Weak Consensus"
    
    def get_summary(self) -> Dict[str, Any]:
        """Get consensus summary."""
        return {
            "final_decision": self.final_decision,
            "consensus_confidence": self.consensus_confidence,
            "agreement_percentage": self.agreement_percentage,
            "consensus_strength": self.consensus_strength,
            "model_count": len(self.model_votes),
            "has_disagreement": self.has_significant_disagreement,
            "strategy_used": self.consensus_strategy_used
        }


@dataclass
class IntegratedValidationResult:
    """
    Complete validation result integrating all Phase 3 analyses.
    
    This combines vulnerability verification, fix quality assessment,
    and consensus results into a single comprehensive result.
    """
    
    # Core components (required field first)
    vulnerability_analysis: VulnerabilityAnalysis
    
    # Optional components with defaults
    fix_quality_analysis: Optional[FixQualityAnalysis] = None
    consensus_result: Optional[ConsensusResult] = None
    
    # Integration metadata with defaults
    validation_timestamp: float = 0.0
    processing_time_seconds: float = 0.0
    ai_model_used: str = ""
    
    # Combined metrics with defaults
    overall_confidence: float = 0.0
    recommended_action: str = ""
    priority_level: str = ""
    
    def __post_init__(self):
        """Calculate combined metrics."""
        # Calculate overall confidence from available analyses
        confidences = [self.vulnerability_analysis.confidence_score]
        
        if self.fix_quality_analysis:
            confidences.append(self.fix_quality_analysis.confidence_score)
        
        if self.consensus_result:
            confidences.append(self.consensus_result.consensus_confidence)
        
        self.overall_confidence = sum(confidences) / len(confidences)
        
        # Determine recommended action
        if self.vulnerability_analysis.is_genuine_vulnerability:
            if self.fix_quality_analysis and self.fix_quality_analysis.is_production_ready:
                self.recommended_action = "Implement suggested fix"
            elif self.fix_quality_analysis:
                self.recommended_action = "Review and improve fix before implementation"
            else:
                self.recommended_action = "Generate and review fix"
        else:
            self.recommended_action = "Mark as false positive"
        
        # Determine priority level
        if self.vulnerability_analysis.is_genuine_vulnerability:
            impact = self.vulnerability_analysis.business_impact_enum
            if impact in [BusinessImpact.CRITICAL, BusinessImpact.HIGH]:
                self.priority_level = "HIGH"
            elif impact == BusinessImpact.MEDIUM:
                self.priority_level = "MEDIUM"
            else:
                self.priority_level = "LOW"
        else:
            self.priority_level = "NONE"
    
    @property
    def requires_immediate_action(self) -> bool:
        """Determine if this requires immediate action."""
        return (self.vulnerability_analysis.is_genuine_vulnerability and
                self.vulnerability_analysis.business_impact_enum == BusinessImpact.CRITICAL and
                self.vulnerability_analysis.exploitability_enum == ExploitabilityLevel.HIGH and
                self.overall_confidence >= 0.8)
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """Get executive summary for reporting."""
        return {
            "is_genuine_vulnerability": self.vulnerability_analysis.is_genuine_vulnerability,
            "overall_confidence": self.overall_confidence,
            "business_impact": self.vulnerability_analysis.business_impact_enum.value,
            "exploitability": self.vulnerability_analysis.exploitability_enum.value,
            "recommended_action": self.recommended_action,
            "priority_level": self.priority_level,
            "requires_immediate_action": self.requires_immediate_action,
            "fix_available": self.fix_quality_analysis is not None,
            "fix_production_ready": (self.fix_quality_analysis.is_production_ready 
                                   if self.fix_quality_analysis else False),
            "consensus_available": self.consensus_result is not None,
            "processing_time": self.processing_time_seconds,
            "ai_model": self.ai_model_used
        }


# Helper functions for creating validation results

def create_error_vulnerability_analysis(error_message: str) -> VulnerabilityAnalysis:
    """Create conservative vulnerability analysis for error cases."""
    return VulnerabilityAnalysis(
        is_genuine_vulnerability=True,  # Conservative assumption
        confidence_score=0.2,  # Low confidence due to error
        false_positive_probability=0.8,  # High uncertainty
        code_context_analysis=f"Analysis failed: {error_message}",
        data_flow_analysis="Unable to analyze due to error",
        business_impact_assessment="MEDIUM",  # Conservative default
        ai_reasoning=f"Verification failed with error: {error_message}. "
                    f"Defaulting to conservative assessment for safety.",
        evidence_citations=[f"Error during analysis: {error_message}"],
        exploitability_level="MEDIUM",
        confidence_factors={"error_occurred": 0.0}
    )


def create_error_fix_quality_analysis(error_message: str) -> FixQualityAnalysis:
    """Create conservative fix quality analysis for error cases."""
    return FixQualityAnalysis(
        overall_quality_score=50.0,  # Neutral score
        completeness_score=50.0,
        implementation_feasibility=50.0,
        security_effectiveness=50.0,
        code_maintainability=50.0,
        performance_impact=50.0,
        improvement_suggestions=[f"Manual review required due to analysis error: {error_message}"],
        security_test_recommendations=["Comprehensive security testing recommended"],
        implementation_guide=f"Analysis failed: {error_message}. Manual review required.",
        potential_side_effects=["Unknown due to analysis failure"],
        addresses_root_cause=False,
        handles_edge_cases=False,
        follows_best_practices=False,
        maintains_functionality=False,
        ai_reasoning=f"Quality analysis failed: {error_message}",
        confidence_score=0.2
    )