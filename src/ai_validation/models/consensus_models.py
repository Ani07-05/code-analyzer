"""Multi-model consensus data structures."""
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
from .ai_models import ModelSize

class ConsensusStrategy(Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_CONFIDENCE = "weighted_confidence"
    UNANIMOUS_REQUIRED = "unanimous_required"
    EXPERT_OVERRIDE = "expert_override"

@dataclass
class ModelVote:
    """Individual model vote in consensus."""
    model_size: ModelSize
    decision: bool
    confidence: float
    reasoning: str
    model_response_time: float

@dataclass
class ConsensusResult:
    """Result of multi-model consensus."""
    final_decision: bool
    confidence_score: float
    model_votes: List[ModelVote]
    consensus_strategy_used: ConsensusStrategy
    disagreement_analysis: Optional[str]
    explanation: str
    trust_score: float
