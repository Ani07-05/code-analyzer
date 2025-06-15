"""Multi-model consensus engine."""
import time
import asyncio
import logging
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass

from ..models.consensus_models import ConsensusResult, ConsensusStrategy, ModelVote
from ..models.ai_models import ModelSize
from ..managers.model_manager import ModelManager


@dataclass
class ConsensusMetrics:
    """Metrics for consensus decision quality."""
    agreement_ratio: float        # 0-1: How much models agree
    confidence_variance: float    # Variance in confidence scores
    decision_strength: float      # 0-1: Strength of final decision
    uncertainty_flag: bool        # True if decision is uncertain


class ConsensusEngine:
    """Multi-model consensus for high-confidence decisions."""
    
    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.logger = logging.getLogger(__name__)
        self.consensus_strategies = {
            ConsensusStrategy.MAJORITY_VOTE: self._majority_vote_consensus,
            ConsensusStrategy.WEIGHTED_CONFIDENCE: self._weighted_confidence_consensus,
        }
        
        # Model size weights for weighted consensus
        self.model_weights = {
            ModelSize.SMALL: 1.0,   # 7B baseline
            ModelSize.MEDIUM: 1.5,  # 13B gets 50% more weight
            ModelSize.LARGE: 2.0    # 34B gets 2x weight
        }
    
    async def get_consensus(self, 
                          task_prompt: str, 
                          models_to_consult: List[ModelSize] = None,
                          strategy: ConsensusStrategy = ConsensusStrategy.WEIGHTED_CONFIDENCE,
                          decision_threshold: float = 0.7) -> ConsensusResult:
        """
        Get multi-model consensus on security decision.
        
        Args:
            task_prompt: The analysis prompt to send to models
            models_to_consult: List of model sizes to consult (default: available models)
            strategy: Consensus strategy to use
            decision_threshold: Minimum confidence for positive decision
            
        Returns:
            ConsensusResult with aggregated decision and metadata
        """
        self.logger.info(f"Starting multi-model consensus with strategy: {strategy.value}")
        start_time = time.time()
        
        try:
            # Determine which models to use
            if models_to_consult is None:
                models_to_consult = await self._get_available_models()
            
            if not models_to_consult:
                raise ValueError("No models available for consensus")
            
            # Collect votes from all models
            votes = await self._collect_model_votes(task_prompt, models_to_consult)
            
            if not votes:
                raise ValueError("No valid votes collected from models")
            
            # Apply consensus strategy
            strategy_func = self.consensus_strategies[strategy]
            final_decision, consensus_confidence = strategy_func(votes)
            
            # Calculate consensus metrics
            metrics = self._calculate_consensus_metrics(votes, final_decision, consensus_confidence)
            
            # Generate detailed reasoning
            reasoning = self._generate_consensus_reasoning(votes, strategy, metrics)
            
            consensus_time = time.time() - start_time
            
            self.logger.info(f"Consensus completed in {consensus_time:.2f}s: {final_decision} (confidence: {consensus_confidence:.3f})")
            
            return ConsensusResult(
                final_decision=final_decision,
                consensus_confidence=consensus_confidence,
                model_votes=votes,
                strategy_used=strategy,
                agreement_ratio=metrics.agreement_ratio,
                uncertainty_flag=metrics.uncertainty_flag,
                detailed_reasoning=reasoning,
                consensus_time_seconds=consensus_time,
                models_consulted=[vote.model_size for vote in votes]
            )
            
        except Exception as e:
            self.logger.error(f"Consensus failed: {e}")
            return self._create_fallback_consensus(str(e))
    
    async def _get_available_models(self) -> List[ModelSize]:
        """Determine which models are available for consensus."""
        available_models = []
        
        # Test each model size to see what's available
        for size in [ModelSize.MEDIUM, ModelSize.SMALL]:  # Prefer larger models first
            try:
                model = await self.model_manager.get_model(size=size, task_complexity="simple")
                if model:
                    available_models.append(size)
                    self.logger.info(f"Model {size.value} available for consensus")
            except Exception as e:
                self.logger.warning(f"Model {size.value} not available: {e}")
        
        return available_models
    
    async def _collect_model_votes(self, prompt: str, models: List[ModelSize]) -> List[ModelVote]:
        """Collect votes from all specified models."""
        self.logger.info(f"Collecting votes from {len(models)} models")
        
        # Create tasks for parallel execution
        vote_tasks = []
        for model_size in models:
            task = self._get_model_vote(prompt, model_size)
            vote_tasks.append(task)
        
        # Execute all votes in parallel
        vote_results = await asyncio.gather(*vote_tasks, return_exceptions=True)
        
        # Filter out failed votes
        valid_votes = []
        for i, result in enumerate(vote_results):
            if isinstance(result, Exception):
                self.logger.warning(f"Vote from {models[i].value} failed: {result}")
            else:
                valid_votes.append(result)
        
        self.logger.info(f"Collected {len(valid_votes)} valid votes")
        return valid_votes
    
    async def _get_model_vote(self, prompt: str, model_size: ModelSize) -> ModelVote:
        """Get vote from a specific model."""
        try:
            # Get model
            model = await self.model_manager.get_model(size=model_size, task_complexity="medium")
            
            # Create consensus-specific prompt
            consensus_prompt = self._create_consensus_prompt(prompt)
            
            # Generate response
            response = await model.generate(
                prompt=consensus_prompt,
                max_tokens=300,
                temperature=0.1  # Low temperature for consistent decisions
            )
            
            # Parse decision and confidence
            decision, confidence, reasoning = self._parse_model_response(response.text)
            
            return ModelVote(
                model_size=model_size,
                decision=decision,
                confidence=confidence,
                reasoning=reasoning,
                response_time=response.generation_time,
                model_weight=self.model_weights[model_size]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get vote from {model_size.value}: {e}")
            # Return neutral vote with low confidence
            return ModelVote(
                model_size=model_size,
                decision=False,
                confidence=0.1,
                reasoning=f"Model vote failed: {e}",
                response_time=0.0,
                model_weight=self.model_weights[model_size]
            )
    
    def _create_consensus_prompt(self, base_prompt: str) -> str:
        """Create a prompt optimized for consensus decision-making."""
        return f"""{base_prompt}

CONSENSUS DECISION REQUIRED:

You must provide a clear decision with confidence level. Analyze the security implications carefully.

RESPONSE FORMAT:
DECISION: [YES/NO] - Is this a genuine security vulnerability?
CONFIDENCE: [0.0-1.0] - How confident are you in this decision?
REASONING: [Brief explanation of your decision]

Example:
DECISION: YES
CONFIDENCE: 0.85
REASONING: Clear SQL injection vulnerability with direct user input concatenation

Your analysis:"""
    
    def _parse_model_response(self, response_text: str) -> Tuple[bool, float, str]:
        """Parse model response into decision, confidence, and reasoning."""
        import re
        
        # Extract decision
        decision_match = re.search(r'DECISION:\s*(YES|NO|TRUE|FALSE)', response_text, re.IGNORECASE)
        if decision_match:
            decision_str = decision_match.group(1).upper()
            decision = decision_str in ['YES', 'TRUE']
        else:
            # Fallback: look for positive/negative indicators
            positive_indicators = ['vulnerable', 'security risk', 'exploit', 'dangerous']
            negative_indicators = ['safe', 'not vulnerable', 'false positive', 'secure']
            
            text_lower = response_text.lower()
            positive_count = sum(1 for indicator in positive_indicators if indicator in text_lower)
            negative_count = sum(1 for indicator in negative_indicators if indicator in text_lower)
            
            decision = positive_count > negative_count
        
        # Extract confidence
        confidence_match = re.search(r'CONFIDENCE:\s*([0-9.]+)', response_text)
        if confidence_match:
            try:
                confidence = float(confidence_match.group(1))
                confidence = max(0.0, min(1.0, confidence))  # Clamp to 0-1
            except ValueError:
                confidence = 0.5
        else:
            confidence = 0.6  # Default confidence
        
        # Extract reasoning
        reasoning_match = re.search(r'REASONING:\s*(.+?)(?=\n[A-Z]+:|$)', response_text, re.DOTALL)
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
        else:
            # Fallback: use first few sentences
            sentences = response_text.replace('\n', ' ').split('.')[:2]
            reasoning = '. '.join(sentences).strip()
            if not reasoning:
                reasoning = "Model provided analysis without clear reasoning"
        
        return decision, confidence, reasoning
    
    def _majority_vote_consensus(self, votes: List[ModelVote]) -> Tuple[bool, float]:
        """Simple majority vote consensus."""
        if not votes:
            return False, 0.0
        
        # Count votes
        positive_votes = sum(1 for vote in votes if vote.decision)
        total_votes = len(votes)
        negative_votes = total_votes - positive_votes
        
        # Determine majority decision
        majority_decision = positive_votes > negative_votes
        
        # Calculate confidence based on majority strength and individual confidences
        if majority_decision:
            relevant_votes = [vote for vote in votes if vote.decision]
        else:
            relevant_votes = [vote for vote in votes if not vote.decision]
        
        if relevant_votes:
            avg_confidence = sum(vote.confidence for vote in relevant_votes) / len(relevant_votes)
            majority_strength = len(relevant_votes) / total_votes
            consensus_confidence = avg_confidence * majority_strength
        else:
            consensus_confidence = 0.5  # Neutral confidence for ties
        
        return majority_decision, consensus_confidence
    
    def _weighted_confidence_consensus(self, votes: List[ModelVote]) -> Tuple[bool, float]:
        """Weighted consensus based on confidence and model size."""
        if not votes:
            return False, 0.0
        
        # Calculate weighted scores
        total_weight = 0.0
        weighted_positive_score = 0.0
        weighted_negative_score = 0.0
        
        for vote in votes:
            weight = vote.model_weight * vote.confidence
            total_weight += weight
            
            if vote.decision:
                weighted_positive_score += weight
            else:
                weighted_negative_score += weight
        
        if total_weight == 0:
            return False, 0.0
        
        # Normalize scores
        positive_ratio = weighted_positive_score / total_weight
        negative_ratio = weighted_negative_score / total_weight
        
        # Final decision
        final_decision = positive_ratio > negative_ratio
        
        # Consensus confidence based on decision strength
        if final_decision:
            consensus_confidence = positive_ratio
        else:
            consensus_confidence = negative_ratio
        
        return final_decision, consensus_confidence
    
    def _calculate_consensus_metrics(self, votes: List[ModelVote], 
                                   final_decision: bool, consensus_confidence: float) -> ConsensusMetrics:
        """Calculate detailed metrics about consensus quality."""
        if not votes:
            return ConsensusMetrics(0.0, 0.0, 0.0, True)
        
        # Agreement ratio: how many models agree with final decision
        agreeing_votes = sum(1 for vote in votes if vote.decision == final_decision)
        agreement_ratio = agreeing_votes / len(votes)
        
        # Confidence variance: how much individual confidences vary
        confidences = [vote.confidence for vote in votes]
        mean_confidence = sum(confidences) / len(confidences)
        confidence_variance = sum((c - mean_confidence) ** 2 for c in confidences) / len(confidences)
        
        # Decision strength: combination of confidence and agreement
        decision_strength = consensus_confidence * agreement_ratio
        
        # Uncertainty flag: true if decision is uncertain
        uncertainty_flag = (
            consensus_confidence < 0.6 or  # Low overall confidence
            agreement_ratio < 0.7 or       # Low agreement
            confidence_variance > 0.1      # High variance in individual confidences
        )
        
        return ConsensusMetrics(
            agreement_ratio=agreement_ratio,
            confidence_variance=confidence_variance,
            decision_strength=decision_strength,
            uncertainty_flag=uncertainty_flag
        )
    
    def _generate_consensus_reasoning(self, votes: List[ModelVote], 
                                    strategy: ConsensusStrategy, metrics: ConsensusMetrics) -> str:
        """Generate detailed reasoning for consensus decision."""
        reasoning_parts = []
        
        # Summary of votes
        positive_votes = [v for v in votes if v.decision]
        negative_votes = [v for v in votes if not v.decision]
        
        reasoning_parts.append(f"CONSENSUS ANALYSIS ({strategy.value.upper()}):")
        reasoning_parts.append(f"Models consulted: {len(votes)} ({[v.model_size.value for v in votes]})")
        reasoning_parts.append(f"Positive votes: {len(positive_votes)}, Negative votes: {len(negative_votes)}")
        reasoning_parts.append(f"Agreement ratio: {metrics.agreement_ratio:.1%}")
        
        # Model-specific reasoning
        if positive_votes:
            reasoning_parts.append("\nPOSITIVE ASSESSMENTS:")
            for vote in positive_votes:
                reasoning_parts.append(f"• {vote.model_size.value} (conf: {vote.confidence:.2f}): {vote.reasoning}")
        
        if negative_votes:
            reasoning_parts.append("\nNEGATIVE ASSESSMENTS:")
            for vote in negative_votes:
                reasoning_parts.append(f"• {vote.model_size.value} (conf: {vote.confidence:.2f}): {vote.reasoning}")
        
        # Uncertainty warning
        if metrics.uncertainty_flag:
            reasoning_parts.append("\n⚠️ UNCERTAINTY WARNING: Models showed disagreement or low confidence")
            reasoning_parts.append("Manual review recommended for this case")
        
        return "\n".join(reasoning_parts)
    
    def _create_fallback_consensus(self, error_message: str) -> ConsensusResult:
        """Create fallback consensus when engine fails."""
        return ConsensusResult(
            final_decision=False,  # Conservative default
            consensus_confidence=0.1,
            model_votes=[],
            strategy_used=ConsensusStrategy.WEIGHTED_CONFIDENCE,
            agreement_ratio=0.0,
            uncertainty_flag=True,
            detailed_reasoning=f"CONSENSUS_FAILED: {error_message}. Manual review required.",
            consensus_time_seconds=0.0,
            models_consulted=[]
        )
