"""Enhanced EntryPoint with AI validation."""
from dataclasses import dataclass
from typing import List, Optional
from ..ai_validation.models.validation_models import VulnerabilityAnalysis

@dataclass
class ValidatedEntryPoint:
    """Enhanced EntryPoint with AI validation results."""
    
    # Original Phase 1 data
    original_entry_point: Any  # Will be actual EntryPoint
    
    # Phase 3 AI validation results
    ai_verification: VulnerabilityAnalysis
    is_validated: bool
    validation_confidence: float
    
    # Enhanced risk assessment
    enhanced_risk_score: float
    business_impact_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    false_positive_probability: float
    
    # Explainable AI
    ai_reasoning: str
    evidence_summary: str
    recommended_priority: str
    
    @property
    def should_fix_immediately(self) -> bool:
        """Determine if this requires immediate fixing."""
        return (self.is_validated and 
                self.validation_confidence > 0.8 and
                self.business_impact_level in ["CRITICAL", "HIGH"])
    
    @property
    def trust_score(self) -> float:
        """Overall trust score combining all factors."""
        base_trust = self.validation_confidence
        
        if self.is_validated and self.false_positive_probability < 0.1:
            base_trust *= 1.2
        
        if self.false_positive_probability > 0.3:
            base_trust *= 0.8
            
        return min(1.0, base_trust)
