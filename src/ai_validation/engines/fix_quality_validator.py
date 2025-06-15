"""AI-powered fix quality validation engine."""
import re
import time
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ..models.validation_models import FixQualityAnalysis
from ..managers.model_manager import ModelManager
from ..models.ai_models import ModelSize


@dataclass
class FixQualityScore:
    """Detailed fix quality scoring."""
    security_effectiveness: float  # 0-100
    implementation_quality: float  # 0-100
    completeness: float           # 0-100
    maintainability: float        # 0-100
    performance_impact: float     # 0-100
    overall_score: float          # 0-100


class FixQualityValidator:
    """AI-powered assessment of fix suggestion quality."""
    
    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.logger = logging.getLogger(__name__)
        self.quality_prompts = self._load_quality_prompts()
    
    async def validate_fix_quality(self, fix_suggestion: str, vulnerability_context: str, 
                                 original_code: str) -> FixQualityAnalysis:
        """
        Comprehensive fix quality validation using AI analysis.
        
        Args:
            fix_suggestion: The proposed code fix
            vulnerability_context: Context about the vulnerability
            original_code: Original vulnerable code
            
        Returns:
            FixQualityAnalysis with detailed scoring and recommendations
        """
        self.logger.info("Starting comprehensive fix quality validation")
        start_time = time.time()
        
        try:
            # Get model for analysis
            model = await self.model_manager.get_model(
                size=ModelSize.MEDIUM,  # Use 13B if available, fallback to 7B
                task_complexity="complex"
            )
            
            # Perform comprehensive analysis
            scores = await self._analyze_fix_quality(
                model, fix_suggestion, vulnerability_context, original_code
            )
            
            # Generate detailed recommendations
            recommendations = await self._generate_recommendations(
                model, fix_suggestion, vulnerability_context, scores
            )
            
            # Calculate overall assessment
            overall_assessment = self._calculate_overall_assessment(scores)
            
            analysis_time = time.time() - start_time
            self.logger.info(f"Fix quality validation completed in {analysis_time:.2f}s")
            
            return FixQualityAnalysis(
                security_effectiveness_score=scores.security_effectiveness,
                implementation_quality_score=scores.implementation_quality,
                completeness_score=scores.completeness,
                maintainability_score=scores.maintainability,
                performance_impact_score=scores.performance_impact,
                overall_quality_score=scores.overall_score,
                detailed_analysis=overall_assessment,
                improvement_recommendations=recommendations,
                analysis_confidence=0.85,  # High confidence with dedicated analysis
                validation_time_seconds=analysis_time
            )
            
        except Exception as e:
            self.logger.error(f"Fix quality validation failed: {e}")
            return self._create_fallback_analysis(str(e))
    
    async def _analyze_fix_quality(self, model, fix_suggestion: str, 
                                 vulnerability_context: str, original_code: str) -> FixQualityScore:
        """Perform detailed AI analysis of fix quality."""
        
        # Create comprehensive analysis prompt
        prompt = self._create_fix_analysis_prompt(
            fix_suggestion, vulnerability_context, original_code
        )
        
        # Generate AI analysis
        response = await model.generate(
            prompt=prompt,
            max_tokens=1000,
            temperature=0.1  # Low temperature for consistent analysis
        )
        
        # Parse response into structured scores
        scores = self._parse_quality_scores(response.text)
        
        return scores
    
    def _create_fix_analysis_prompt(self, fix_suggestion: str, 
                                  vulnerability_context: str, original_code: str) -> str:
        """Create comprehensive prompt for fix quality analysis."""
        
        return f"""You are a senior security engineer performing a comprehensive code fix review.

VULNERABILITY CONTEXT:
{vulnerability_context}

ORIGINAL VULNERABLE CODE:
```
{original_code}
```

PROPOSED FIX:
```
{fix_suggestion}
```

COMPREHENSIVE ANALYSIS REQUIRED:

1. SECURITY EFFECTIVENESS (0-100):
   - Does this fix completely eliminate the vulnerability?
   - Are there any remaining attack vectors?
   - Does it introduce new security risks?
   - Rate the security effectiveness (0 = ineffective, 100 = perfect)

2. IMPLEMENTATION QUALITY (0-100):
   - Is the code well-structured and readable?
   - Does it follow coding best practices?
   - Are there any syntax or logical errors?
   - Rate the implementation quality (0 = poor, 100 = excellent)

3. COMPLETENESS (0-100):
   - Does the fix address all aspects of the vulnerability?
   - Are edge cases properly handled?
   - Is input validation comprehensive?
   - Rate the completeness (0 = incomplete, 100 = comprehensive)

4. MAINTAINABILITY (0-100):
   - Is the code easy to understand and modify?
   - Are there proper comments and documentation?
   - Does it integrate well with existing codebase?
   - Rate the maintainability (0 = hard to maintain, 100 = very maintainable)

5. PERFORMANCE IMPACT (0-100):
   - What is the performance impact of this fix?
   - Are there more efficient alternatives?
   - Does it scale well?
   - Rate the performance (0 = severe impact, 100 = no impact/improvement)

FORMAT YOUR RESPONSE AS:
SECURITY_EFFECTIVENESS: [score 0-100]
SECURITY_ANALYSIS: [detailed analysis]

IMPLEMENTATION_QUALITY: [score 0-100]
IMPLEMENTATION_ANALYSIS: [detailed analysis]

COMPLETENESS: [score 0-100]
COMPLETENESS_ANALYSIS: [detailed analysis]

MAINTAINABILITY: [score 0-100]
MAINTAINABILITY_ANALYSIS: [detailed analysis]

PERFORMANCE_IMPACT: [score 0-100]
PERFORMANCE_ANALYSIS: [detailed analysis]

OVERALL_ASSESSMENT: [comprehensive summary]
CRITICAL_ISSUES: [list any critical problems]
RECOMMENDATIONS: [specific improvement suggestions]

Begin comprehensive analysis:"""
    
    def _parse_quality_scores(self, response_text: str) -> FixQualityScore:
        """Parse AI response into structured quality scores."""
        
        # Extract scores using regex patterns
        security_score = self._extract_score(response_text, r'SECURITY_EFFECTIVENESS:\s*(\d+)')
        implementation_score = self._extract_score(response_text, r'IMPLEMENTATION_QUALITY:\s*(\d+)')
        completeness_score = self._extract_score(response_text, r'COMPLETENESS:\s*(\d+)')
        maintainability_score = self._extract_score(response_text, r'MAINTAINABILITY:\s*(\d+)')
        performance_score = self._extract_score(response_text, r'PERFORMANCE_IMPACT:\s*(\d+)')
        
        # Calculate weighted overall score
        # Security is most important, followed by completeness
        overall_score = (
            security_score * 0.35 +           # Security: 35%
            completeness_score * 0.25 +       # Completeness: 25%
            implementation_score * 0.2 +      # Implementation: 20%
            maintainability_score * 0.15 +    # Maintainability: 15%
            performance_score * 0.05          # Performance: 5%
        )
        
        return FixQualityScore(
            security_effectiveness=security_score,
            implementation_quality=implementation_score,
            completeness=completeness_score,
            maintainability=maintainability_score,
            performance_impact=performance_score,
            overall_score=overall_score
        )
    
    def _extract_score(self, text: str, pattern: str) -> float:
        """Extract numerical score from response text."""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
                return max(0.0, min(100.0, score))  # Clamp to 0-100
            except ValueError:
                pass
        return 70.0  # Default score if parsing fails
    
    async def _generate_recommendations(self, model, fix_suggestion: str, 
                                      vulnerability_context: str, scores: FixQualityScore) -> List[str]:
        """Generate specific improvement recommendations."""
        
        prompt = f"""Based on the fix quality analysis, provide specific actionable recommendations:

FIX QUALITY SCORES:
- Security Effectiveness: {scores.security_effectiveness}/100
- Implementation Quality: {scores.implementation_quality}/100
- Completeness: {scores.completeness}/100
- Maintainability: {scores.maintainability}/100
- Performance Impact: {scores.performance_impact}/100

PROPOSED FIX:
```
{fix_suggestion}
```

Provide 3-5 specific, actionable recommendations to improve this fix:

RECOMMENDATIONS:
1. [Specific improvement suggestion]
2. [Specific improvement suggestion]
3. [Specific improvement suggestion]
4. [Optional additional suggestion]
5. [Optional additional suggestion]

Focus on the areas with lowest scores and provide concrete code improvements."""
        
        response = await model.generate(
            prompt=prompt,
            max_tokens=500,
            temperature=0.2
        )
        
        # Parse recommendations from response
        recommendations = self._parse_recommendations(response.text)
        
        return recommendations
    
    def _parse_recommendations(self, response_text: str) -> List[str]:
        """Parse recommendations from AI response."""
        recommendations = []
        
        # Extract numbered recommendations
        pattern = r'\d+\.\s*(.+?)(?=\n\d+\.|\n[A-Z]+:|$)'
        matches = re.findall(pattern, response_text, re.DOTALL)
        
        for match in matches:
            recommendation = match.strip()
            if recommendation and len(recommendation) > 10:  # Filter out empty/short matches
                recommendations.append(recommendation)
        
        # Fallback: split by lines and filter
        if not recommendations:
            lines = response_text.split('\n')
            for line in lines:
                line = line.strip()
                if line and any(line.startswith(prefix) for prefix in ['1.', '2.', '3.', '4.', '5.', '-', '*']):
                    clean_line = re.sub(r'^\d+\.\s*', '', line)
                    clean_line = re.sub(r'^[-*]\s*', '', clean_line)
                    if clean_line and len(clean_line) > 10:
                        recommendations.append(clean_line)
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def _calculate_overall_assessment(self, scores: FixQualityScore) -> str:
        """Calculate overall assessment based on scores."""
        
        if scores.overall_score >= 90:
            quality_level = "EXCELLENT"
            assessment = "This fix demonstrates exceptional quality across all dimensions."
        elif scores.overall_score >= 80:
            quality_level = "GOOD"
            assessment = "This fix is well-implemented with minor areas for improvement."
        elif scores.overall_score >= 70:
            quality_level = "ACCEPTABLE"
            assessment = "This fix addresses the vulnerability but has notable quality issues."
        elif scores.overall_score >= 60:
            quality_level = "NEEDS_IMPROVEMENT"
            assessment = "This fix has significant quality issues that should be addressed."
        else:
            quality_level = "POOR"
            assessment = "This fix has major quality problems and requires substantial revision."
        
        # Add specific concerns
        concerns = []
        if scores.security_effectiveness < 80:
            concerns.append("security effectiveness")
        if scores.completeness < 70:
            concerns.append("completeness")
        if scores.implementation_quality < 70:
            concerns.append("implementation quality")
        
        if concerns:
            assessment += f" Primary concerns: {', '.join(concerns)}."
        
        return f"{quality_level}: {assessment}"
    
    def _create_fallback_analysis(self, error_message: str) -> FixQualityAnalysis:
        """Create fallback analysis when AI validation fails."""
        return FixQualityAnalysis(
            security_effectiveness_score=50.0,
            implementation_quality_score=50.0,
            completeness_score=50.0,
            maintainability_score=50.0,
            performance_impact_score=50.0,
            overall_quality_score=50.0,
            detailed_analysis=f"ANALYSIS_FAILED: Unable to perform AI validation due to: {error_message}. Manual review recommended.",
            improvement_recommendations=[
                "Manual security review required due to AI analysis failure",
                "Verify fix addresses all attack vectors",
                "Test fix thoroughly in development environment",
                "Consider peer review by security expert"
            ],
            analysis_confidence=0.1,  # Low confidence for fallback
            validation_time_seconds=0.0
        )
    
    def _load_quality_prompts(self) -> Dict[str, str]:
        """Load prompts for fix quality assessment."""
        return {
            "security_analysis": "Analyze the security effectiveness of this fix...",
            "implementation_review": "Review the implementation quality and best practices...",
            "completeness_check": "Assess if this fix completely addresses the vulnerability...",
            "maintainability_assessment": "Evaluate the maintainability and code quality...",
            "performance_evaluation": "Analyze the performance impact of this fix..."
        }
