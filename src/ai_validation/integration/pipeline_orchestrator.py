"""
Complete AI Validation Pipeline Orchestrator
File: src/ai_validation/integration/pipeline_orchestrator.py

Orchestrates the complete vulnerability analysis pipeline:
Phase 1: Entry Point Detection → Phase 2: RAG Fix Generation → Phase 3: AI Validation
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

# Phase 1 imports
import sys
from pathlib import Path
try:
    from entry_detector.main import EntryPointDetector
    from entry_detector.models import EntryPoint
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from entry_detector.main import EntryPointDetector
    from entry_detector.models import EntryPoint

# Phase 2 imports
try:
    from rag_system.models import FixSuggestion
    from rag_system.agents.security_agent import SecurityFixAgent
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from rag_system.models import FixSuggestion
    from rag_system.agents.security_agent import SecurityFixAgent

# Phase 3 imports
from ..managers.model_manager import ModelManager
from ..engines.vulnerability_verifier import DynamicVulnerabilityVerifier
from ..engines.fix_quality_validator import FixQualityValidator
from ..engines.consensus_engine import ConsensusEngine
from ..models.consensus_models import ConsensusStrategy

# Integration
from .phase_connector import PhaseConnector, ValidationRequest, ValidationResult


class PipelineOrchestrator:
    """
    Complete vulnerability analysis pipeline orchestrator.
    
    Coordinates all three phases of vulnerability detection and validation:
    1. Phase 1: Entry point detection and risk assessment
    2. Phase 2: RAG-powered fix generation with citations
    3. Phase 3: AI validation of vulnerabilities and fix quality
    """
    
    def __init__(self, 
                 enable_ai_validation: bool = True,
                 model_manager: Optional[ModelManager] = None,
                 consensus_strategy: ConsensusStrategy = ConsensusStrategy.WEIGHTED_CONFIDENCE):
        """
        Initialize the complete pipeline.
        
        Args:
            enable_ai_validation: Whether to enable Phase 3 AI validation
            model_manager: ModelManager instance (created if None)
            consensus_strategy: Strategy for multi-model consensus
        """
        self.enable_ai_validation = enable_ai_validation
        self.consensus_strategy = consensus_strategy
        self.logger = logging.getLogger(__name__)
        
        # Initialize Phase 1 components
        self.entry_detector = EntryPointDetector()
        
        # Initialize Phase 2 components
        self.security_agent = SecurityFixAgent()
        
        # Initialize Phase 3 components (if enabled)
        if enable_ai_validation:
            self.model_manager = model_manager or ModelManager()
            self.vulnerability_verifier = DynamicVulnerabilityVerifier(self.model_manager)
            self.fix_validator = FixQualityValidator(self.model_manager)
            self.consensus_engine = ConsensusEngine(self.model_manager)
            self.phase_connector = PhaseConnector()
        
        self.logger.info(f"Pipeline orchestrator initialized (AI validation: {enable_ai_validation})")
    
    async def analyze_project(self, project_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run complete vulnerability analysis on a project.
        
        Args:
            project_path: Path to the project to analyze
            **kwargs: Additional options for analysis
            
        Returns:
            Complete analysis results with all phases
        """
        start_time = time.time()
        self.logger.info(f"Starting complete project analysis: {project_path}")
        
        try:
            # Phase 1: Entry Point Detection
            self.logger.info("🔍 Phase 1: Entry Point Detection")
            phase1_start = time.time()
            
            entry_points = await self._run_phase1(project_path, **kwargs)
            phase1_time = time.time() - phase1_start
            
            self.logger.info(f"Phase 1 completed in {phase1_time:.2f}s: {len(entry_points)} entry points found")
            
            if not entry_points:
                return self._create_empty_results("No vulnerabilities detected", phase1_time)
            
            # Phase 2: RAG Fix Generation
            self.logger.info("🛠️ Phase 2: RAG Fix Generation")
            phase2_start = time.time()
            
            fix_suggestions = await self._run_phase2(entry_points, project_path, **kwargs)
            phase2_time = time.time() - phase2_start
            
            self.logger.info(f"Phase 2 completed in {phase2_time:.2f}s: {len(fix_suggestions)} fixes generated")
            
            # Phase 3: AI Validation (if enabled)
            validation_results = []
            phase3_time = 0.0
            
            if self.enable_ai_validation:
                self.logger.info("🤖 Phase 3: AI Validation")
                phase3_start = time.time()
                
                validation_results = await self._run_phase3(entry_points, fix_suggestions, project_path, **kwargs)
                phase3_time = time.time() - phase3_start
                
                self.logger.info(f"Phase 3 completed in {phase3_time:.2f}s: {len(validation_results)} validations performed")
            
            total_time = time.time() - start_time
            
            # Compile final results
            results = self._compile_results(
                entry_points, fix_suggestions, validation_results,
                phase1_time, phase2_time, phase3_time, total_time
            )
            
            self.logger.info(f"Complete analysis finished in {total_time:.2f}s")
            return results
            
        except Exception as e:
            self.logger.error(f"Pipeline analysis failed: {e}")
            return {"error": str(e), "analysis_time": time.time() - start_time}
    
    async def _run_phase1(self, project_path: str, **kwargs) -> List[EntryPoint]:
        """Run Phase 1: Entry Point Detection."""
        
        try:
            # Use existing entry detector
            # This calls the Phase 1 implementation
            entry_points = self.entry_detector.detect_entry_points(project_path)
            
            # Apply risk assessment
            assessed_entry_points = self.entry_detector.assess_risks(entry_points)
            
            return assessed_entry_points
            
        except Exception as e:
            self.logger.error(f"Phase 1 failed: {e}")
            return []
    
    async def _run_phase2(self, entry_points: List[EntryPoint], 
                         project_path: str, **kwargs) -> List[FixSuggestion]:
        """Run Phase 2: RAG Fix Generation."""
        
        try:
            fix_suggestions = []
            
            for entry_point in entry_points:
                # Generate fix using RAG system
                fix = await self.security_agent.generate_fix(
                    vulnerability=entry_point,
                    project_context={"project_path": project_path}
                )
                
                if fix:
                    fix_suggestions.append(fix)
            
            return fix_suggestions
            
        except Exception as e:
            self.logger.error(f"Phase 2 failed: {e}")
            return []
    
    async def _run_phase3(self, entry_points: List[EntryPoint],
                         fix_suggestions: List[FixSuggestion],
                         project_path: str, **kwargs) -> List[ValidationResult]:
        """Run Phase 3: AI Validation."""
        
        try:
            # Create validation requests
            validation_requests = self.phase_connector.create_validation_requests(
                entry_points, fix_suggestions, project_path
            )
            
            if not validation_requests:
                self.logger.warning("No validation requests created")
                return []
            
            # Process all validation requests
            validation_results = []
            
            for request in validation_requests:
                result = await self._process_validation_request(request)
                if result:
                    validation_results.append(result)
            
            return validation_results
            
        except Exception as e:
            self.logger.error(f"Phase 3 failed: {e}")
            return []
    
    async def _process_validation_request(self, request: ValidationRequest) -> Optional[ValidationResult]:
        """Process a single validation request through all AI engines."""
        
        try:
            self.logger.debug(f"Processing validation for {request.entry_point.function_name}")
            
            # Run all validation engines in parallel for efficiency
            vulnerability_task = self.vulnerability_verifier.verify_vulnerability(
                request.entry_point,
                request.source_code,
                request.project_context
            )
            
            fix_quality_task = self.fix_validator.validate_fix_quality(
                request.fix_suggestion.suggested_fix,
                f"Vulnerability in {request.entry_point.function_name}",
                request.source_code
            )
            
            # Create consensus prompt for the vulnerability
            consensus_prompt = self._create_consensus_prompt(request)
            consensus_task = self.consensus_engine.get_consensus(
                consensus_prompt,
                strategy=self.consensus_strategy
            )
            
            # Wait for all analyses to complete
            vulnerability_analysis, fix_quality_analysis, consensus_result = await asyncio.gather(
                vulnerability_task, fix_quality_task, consensus_task
            )
            
            # Aggregate results
            validation_result = self.phase_connector.aggregate_validation_results(
                vulnerability_analysis,
                fix_quality_analysis,
                consensus_result,
                request.entry_point,
                request.fix_suggestion
            )
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Validation request failed for {request.entry_point.function_name}: {e}")
            return None
    
    def _create_consensus_prompt(self, request: ValidationRequest) -> str:
        """Create consensus prompt for multi-model validation."""
        
        vuln_context = f"""
VULNERABILITY ANALYSIS REQUEST:

File: {request.entry_point.file_path}
Function: {request.entry_point.function_name}
Line: {request.entry_point.line_start}-{request.entry_point.line_end}
Risk Score: {request.entry_point.risk_score}/100
Risk Factors: {', '.join(request.entry_point.risk_factors)}

SOURCE CODE:
```python
{request.source_code}
```

PROPOSED FIX:
```python
{request.fix_suggestion.suggested_fix}
```

ANALYSIS QUESTION:
Is this a genuine security vulnerability that requires the proposed fix?
Consider: attack vectors, exploitability, business impact, and fix effectiveness.
"""
        return vuln_context
    
    def _compile_results(self, entry_points: List[EntryPoint],
                        fix_suggestions: List[FixSuggestion],
                        validation_results: List[ValidationResult],
                        phase1_time: float, phase2_time: float, phase3_time: float,
                        total_time: float) -> Dict[str, Any]:
        """Compile complete analysis results."""
        
        results = {
            "analysis_summary": {
                "total_entry_points": len(entry_points),
                "total_fixes_generated": len(fix_suggestions),
                "total_validations": len(validation_results),
                "ai_validation_enabled": self.enable_ai_validation
            },
            "timing": {
                "phase1_detection_seconds": round(phase1_time, 2),
                "phase2_fix_generation_seconds": round(phase2_time, 2),
                "phase3_ai_validation_seconds": round(phase3_time, 2),
                "total_analysis_seconds": round(total_time, 2)
            },
            "entry_points": [self._serialize_entry_point(ep) for ep in entry_points],
            "fix_suggestions": [self._serialize_fix_suggestion(fix) for fix in fix_suggestions],
        }
        
        # Add AI validation results if available
        if validation_results:
            results["ai_validation"] = {
                "validation_results": [self._serialize_validation_result(vr) for vr in validation_results],
                "validation_summary": self.phase_connector.create_validation_summary(validation_results)
            }
        
        return results
    
    def _create_empty_results(self, message: str, analysis_time: float) -> Dict[str, Any]:
        """Create empty results structure."""
        return {
            "analysis_summary": {
                "total_entry_points": 0,
                "total_fixes_generated": 0,
                "total_validations": 0,
                "message": message
            },
            "timing": {
                "total_analysis_seconds": round(analysis_time, 2)
            },
            "entry_points": [],
            "fix_suggestions": []
        }
    
    def _serialize_entry_point(self, entry_point: EntryPoint) -> Dict[str, Any]:
        """Serialize entry point for JSON output."""
        return {
            "function_name": entry_point.function_name,
            "file_path": entry_point.file_path,
            "line_start": entry_point.line_start,
            "line_end": entry_point.line_end,
            "risk_score": entry_point.risk_score,
            "risk_factors": entry_point.risk_factors,
            "business_impact": entry_point.business_impact,
            "vulnerability_type": getattr(entry_point, 'vulnerability_type', 'Unknown')
        }
    
    def _serialize_fix_suggestion(self, fix: FixSuggestion) -> Dict[str, Any]:
        """Serialize fix suggestion for JSON output."""
        return {
            "vulnerability_description": getattr(fix, 'vulnerability_description', ''),
            "suggested_fix": fix.suggested_fix,
            "explanation": getattr(fix, 'explanation', ''),
            "stack_overflow_citations": getattr(fix, 'stack_overflow_citations', []),
            "confidence_score": getattr(fix, 'confidence_score', 0.0)
        }
    
    def _serialize_validation_result(self, result: ValidationResult) -> Dict[str, Any]:
        """Serialize validation result for JSON output."""
        return {
            "function_name": result.entry_point.function_name,
            "is_genuine_vulnerability": result.vulnerability_analysis.is_genuine_vulnerability,
            "vulnerability_confidence": result.vulnerability_analysis.confidence_score,
            "fix_quality_score": result.fix_quality_analysis.overall_quality_score,
            "consensus_decision": result.consensus_result.final_decision,
            "consensus_confidence": result.consensus_result.consensus_confidence,
            "overall_confidence": result.overall_confidence,
            "recommendation": result.recommendation,
            "ai_reasoning": result.vulnerability_analysis.ai_reasoning,
            "fix_recommendations": result.fix_quality_analysis.improvement_recommendations,
            "uncertainty_flag": result.consensus_result.uncertainty_flag
        }
    
    async def analyze_single_vulnerability(self, file_path: str, function_name: str, 
                                         project_path: str) -> Dict[str, Any]:
        """Analyze a single specific vulnerability through the complete pipeline."""
        
        self.logger.info(f"Analyzing single vulnerability: {function_name} in {file_path}")
        
        try:
            # Find the specific entry point
            all_entry_points = await self._run_phase1(project_path)
            target_entry_point = None
            
            for ep in all_entry_points:
                if ep.function_name == function_name and ep.file_path == file_path:
                    target_entry_point = ep
                    break
            
            if not target_entry_point:
                return {"error": f"Vulnerability not found: {function_name} in {file_path}"}
            
            # Run complete pipeline for this single vulnerability
            return await self.analyze_project(
                project_path, 
                filter_function=function_name,
                filter_file=file_path
            )
            
        except Exception as e:
            self.logger.error(f"Single vulnerability analysis failed: {e}")
            return {"error": str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get status of all pipeline components."""
        status = {
            "pipeline_enabled": True,
            "ai_validation_enabled": self.enable_ai_validation,
            "phase1_detector": "operational",
            "phase2_rag_system": "operational"
        }
        
        if self.enable_ai_validation:
            status.update({
                "phase3_ai_validation": "operational",
                "model_manager_status": self.model_manager.get_system_status(),
                "consensus_strategy": self.consensus_strategy.value
            })
        
        return status