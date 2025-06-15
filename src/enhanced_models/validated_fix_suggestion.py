"""Enhanced FixSuggestion with AI validation."""
from dataclasses import dataclass
from typing import List
from ..ai_validation.models.validation_models import FixQualityAnalysis

@dataclass
class ValidatedFixSuggestion:
    """Enhanced FixSuggestion with AI quality validation."""
    
    # Original Phase 2 data
    original_fix: Any  # Will be actual FixSuggestion
    
    # Phase 3 quality validation
    quality_analysis: FixQualityAnalysis
    is_implementation_ready: bool
    
    # Enhanced confidence metrics
    combined_confidence_score: float
    implementation_feasibility: float
    security_effectiveness: float
    
    # Implementation guidance
    step_by_step_guide: List[str]
    potential_side_effects: List[str]
    testing_recommendations: List[str]
    
    # Quality improvements
    ai_improvement_suggestions: List[str]
    code_quality_score: float
    
    @property
    def is_production_ready(self) -> bool:
        """Determine if fix is ready for production."""
        return (self.is_implementation_ready and
                self.combined_confidence_score > 85.0 and
                self.security_effectiveness > 90.0 and
                self.implementation_feasibility > 80.0)
    
    @property
    def overall_quality_grade(self) -> str:
        """Letter grade for overall fix quality."""
        score = self.combined_confidence_score
        if score >= 95: return "A+"
        elif score >= 90: return "A"
        elif score >= 85: return "B+"
        elif score >= 80: return "B"
        elif score >= 75: return "C+"
        elif score >= 70: return "C"
        else: return "D"
