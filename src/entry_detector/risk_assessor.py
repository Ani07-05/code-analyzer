"""
Business Impact Risk Assessor

Implements business-focused risk assessment based on real-world impact:
- HIGH: Business-ending damage (system compromise, mass data leaks)
- MODERATE: Individual user impact (account compromise, personal data)
- LOW: Technical debt (deprecated packages, performance issues)
"""

import logging
from typing import List, Dict, Tuple, Any
from .models import EntryPoint, RiskLevel, InputSourceType

logger = logging.getLogger(__name__)


class RiskAssessor:
    """
    Business impact-focused risk assessment engine
    
    Calculates risk based on potential business damage rather than just
    technical severity. Prioritizes vulnerabilities that could:
    - Damage entire system infrastructure
    - Leak massive amounts of user data
    - Compromise system integrity and cause downtime
    """
    
    def __init__(self):
        # Load risk calculation rules
        self.high_risk_threshold = 70
        self.moderate_risk_threshold = 40
        
        # Business impact multipliers
        self.business_multipliers = {
            'payment_data': 2.0,
            'admin_access': 1.8,
            'mass_user_data': 1.6,
            'system_commands': 1.5,
            'unauthenticated_access': 1.4,
        }
    
    def assess_risk(self, entry_point: EntryPoint) -> EntryPoint:
        """
        Assess business risk for an entry point
        
        Args:
            entry_point: Entry point to assess
            
        Returns:
            Entry point with updated risk level and score
        """
        # Calculate base risk score
        base_score = self._calculate_base_risk_score(entry_point)
        
        # Apply business impact multipliers
        business_score = self._apply_business_multipliers(entry_point, base_score)
        
        # Determine risk level based on business impact
        risk_level, final_score = self._determine_risk_level(entry_point, business_score)
        
        # Update entry point
        entry_point.risk_level = risk_level
        entry_point.risk_score = min(100, int(final_score))
        entry_point.risk_factors = self._generate_risk_factors(entry_point)
        
        logger.debug(f"Risk assessment for {entry_point.function_name}: "
                    f"{risk_level.value} (score: {entry_point.risk_score})")
        
        return entry_point
    
    def _calculate_base_risk_score(self, entry_point: EntryPoint) -> float:
        """Calculate base risk score from technical factors"""
        score = 0.0
        
        # External input handling (foundation of most vulnerabilities)
        if entry_point.external_input_count > 0:
            score += 20 + (entry_point.external_input_count * 5)
        
        # Database access (SQL injection potential)
        if entry_point.database_access:
            score += 25
            # Extra risk if database + external input without validation
            if entry_point.external_input_count > 0 and not entry_point.input_validation_present:
                score += 20
        
        # File system access (path traversal, file upload vulnerabilities)
        if entry_point.file_system_access:
            score += 15
            # Higher risk if handling file uploads
            if any(src.source_type == InputSourceType.FILE_UPLOAD for src in entry_point.input_sources):
                score += 15
        
        # System command execution (RCE potential)
        if entry_point.system_command_execution:
            score += 30
        
        # Web endpoints are higher risk (external attack surface)
        if entry_point.is_web_endpoint():
            score += 10
            # API endpoints often handle sensitive data
            if entry_point.route_info and '/api/' in entry_point.route_info.url_pattern:
                score += 10
        
        # Missing security controls
        security_gaps = self._count_security_gaps(entry_point)
        score += security_gaps * 8
        
        return score
    
    def _apply_business_multipliers(self, entry_point: EntryPoint, base_score: float) -> float:
        """Apply business impact multipliers to base score"""
        multiplier = 1.0
        
        # CRITICAL BUSINESS IMPACT FACTORS
        
        # Payment data handling = highest multiplier
        if entry_point.handles_payment_data:
            multiplier *= self.business_multipliers['payment_data']
        
        # Admin privileges = can damage entire system
        if entry_point.has_admin_privileges:
            multiplier *= self.business_multipliers['admin_access']
        
        # Mass user data access = privacy breach potential
        if self._can_access_mass_user_data(entry_point):
            multiplier *= self.business_multipliers['mass_user_data']
        
        # System command execution = full system compromise
        if entry_point.system_command_execution:
            multiplier *= self.business_multipliers['system_commands']
        
        # Unauthenticated access to sensitive operations
        if self._is_sensitive_unauthenticated_access(entry_point):
            multiplier *= self.business_multipliers['unauthenticated_access']
        
        return base_score * multiplier
    
    def _determine_risk_level(self, entry_point: EntryPoint, business_score: float) -> Tuple[RiskLevel, float]:
        """
        Determine final risk level based on business impact potential
        
        HIGH = Business-ending damage
        MODERATE = Individual user impact  
        LOW = Technical debt, performance issues
        """
        
        # HIGH RISK: Business-ending damage potential
        if self._is_business_ending_risk(entry_point, business_score):
            return RiskLevel.HIGH, business_score
        
        # MODERATE RISK: Individual user impact
        elif self._is_individual_user_impact(entry_point, business_score):
            return RiskLevel.MODERATE, min(business_score, 80)  # Cap moderate risk
        
        # LOW RISK: Technical debt, performance
        else:
            return RiskLevel.LOW, min(business_score, 50)  # Cap low risk
    
    def _is_business_ending_risk(self, entry_point: EntryPoint, score: float) -> bool:
        """
        Check if this entry point could cause business-ending damage
        
        Business-ending scenarios:
        - Mass data breach (all user data leaked)
        - System infrastructure compromise
        - Payment system compromise
        - Complete service outage
        """
        
        # Score-based threshold
        if score >= self.high_risk_threshold:
            return True
        
        # Specific high-risk scenarios regardless of score
        high_risk_scenarios = [
            # Payment data + external input + no validation = credit card breach
            (entry_point.handles_payment_data and 
             entry_point.external_input_count > 0 and 
             not entry_point.input_validation_present),
            
            # Admin access + external input + no auth = system takeover
            (entry_point.has_admin_privileges and 
             entry_point.external_input_count > 0 and 
             not entry_point.authentication_required),
            
            # System commands + external input = RCE
            (entry_point.system_command_execution and 
             entry_point.external_input_count > 0),
            
            # Mass user data + database + no auth = data breach
            (self._can_access_mass_user_data(entry_point) and 
             entry_point.database_access and 
             not entry_point.authentication_required),
            
            # Config modification + external input = system compromise
            (entry_point.can_modify_system_config and 
             entry_point.external_input_count > 0),
        ]
        
        return any(high_risk_scenarios)
    
    def _is_individual_user_impact(self, entry_point: EntryPoint, score: float) -> bool:
        """
        Check if this affects individual users but not the entire business
        
        Individual user impact scenarios:
        - Single user account compromise
        - Personal data access
        - User session manipulation
        """
        
        # Score-based threshold
        if score >= self.moderate_risk_threshold:
            return True
        
        # Specific moderate-risk scenarios
        moderate_risk_scenarios = [
            # User data access with external input
            (entry_point.accesses_user_data and 
             entry_point.external_input_count > 0),
            
            # Database access with external input (could be SQL injection)
            (entry_point.database_access and 
             entry_point.external_input_count > 0),
            
            # Authenticated endpoints with input validation gaps
            (entry_point.authentication_required and 
             entry_point.external_input_count > 0 and 
             not entry_point.input_validation_present),
            
            # File system access with external input
            (entry_point.file_system_access and 
             entry_point.external_input_count > 0),
        ]
        
        return any(moderate_risk_scenarios)
    
    def _can_access_mass_user_data(self, entry_point: EntryPoint) -> bool:
        """Check if entry point can access data from multiple users"""
        mass_data_indicators = [
            entry_point.has_admin_privileges,
            # Look for patterns that suggest bulk data access
            'users' in entry_point.source_code.lower(),
            'all_users' in entry_point.source_code.lower(),
            'user_list' in entry_point.source_code.lower(),
            # Admin-style routes
            entry_point.route_info and '/admin' in entry_point.route_info.url_pattern if entry_point.route_info else False,
            # Export/download functionality
            'export' in entry_point.function_name.lower(),
            'download' in entry_point.function_name.lower(),
            'dump' in entry_point.function_name.lower(),
        ]
        
        return any(mass_data_indicators)
    
    def _is_sensitive_unauthenticated_access(self, entry_point: EntryPoint) -> bool:
        """Check if sensitive operations are accessible without authentication"""
        if entry_point.authentication_required:
            return False
        
        sensitive_operations = [
            entry_point.database_access,
            entry_point.accesses_user_data,
            entry_point.file_system_access,
            entry_point.handles_payment_data,
            entry_point.can_modify_system_config,
        ]
        
        return any(sensitive_operations)
    
    def _count_security_gaps(self, entry_point: EntryPoint) -> int:
        """Count missing security controls"""
        gaps = 0
        
        # Input validation missing for endpoints with external input
        if entry_point.external_input_count > 0 and not entry_point.input_validation_present:
            gaps += 1
        
        # Authentication missing for sensitive operations
        if self._requires_authentication(entry_point) and not entry_point.authentication_required:
            gaps += 2  # Higher weight for missing auth
        
        # Output encoding missing for web endpoints
        if entry_point.is_web_endpoint() and not entry_point.output_encoding_present:
            gaps += 1
        
        # CSRF protection missing for state-changing operations
        if self._is_state_changing_operation(entry_point) and not entry_point.csrf_protection:
            gaps += 1
        
        return gaps
    
    def _requires_authentication(self, entry_point: EntryPoint) -> bool:
        """Check if this entry point should require authentication"""
        auth_required_indicators = [
            entry_point.accesses_user_data,
            entry_point.database_access,
            entry_point.file_system_access,
            entry_point.handles_payment_data,
            entry_point.has_admin_privileges,
            entry_point.can_modify_system_config,
        ]
        
        return any(auth_required_indicators)
    
    def _is_state_changing_operation(self, entry_point: EntryPoint) -> bool:
        """Check if this operation changes system state (needs CSRF protection)"""
        if not entry_point.route_info:
            return False
        
        # State-changing HTTP methods
        state_changing_methods = {'POST', 'PUT', 'PATCH', 'DELETE'}
        has_state_changing_method = any(
            method in state_changing_methods 
            for method in entry_point.route_info.http_methods
        )
        
        # Operations that likely change state
        state_changing_patterns = [
            'create', 'update', 'delete', 'modify', 'save', 'submit',
            'login', 'logout', 'register', 'upload', 'send'
        ]
        
        has_state_changing_name = any(
            pattern in entry_point.function_name.lower() 
            for pattern in state_changing_patterns
        )
        
        return has_state_changing_method or has_state_changing_name
    
    def _generate_risk_factors(self, entry_point: EntryPoint) -> List[str]:
        """Generate human-readable risk factors"""
        factors = []
        
        # High-impact factors
        if entry_point.handles_payment_data:
            factors.append("Handles payment/financial data")
        
        if entry_point.has_admin_privileges:
            factors.append("Administrative privileges")
        
        if entry_point.system_command_execution:
            factors.append("System command execution")
        
        if self._can_access_mass_user_data(entry_point):
            factors.append("Mass user data access")
        
        # Security gaps
        if entry_point.external_input_count > 0 and not entry_point.input_validation_present:
            factors.append(f"Unvalidated external input ({entry_point.external_input_count} sources)")
        
        if not entry_point.authentication_required and self._requires_authentication(entry_point):
            factors.append("Missing authentication for sensitive operation")
        
        if entry_point.database_access and entry_point.external_input_count > 0:
            factors.append("SQL injection potential")
        
        if entry_point.is_web_endpoint() and not entry_point.output_encoding_present:
            factors.append("XSS vulnerability potential")
        
        # Input source risks
        risky_input_types = [
            InputSourceType.FILE_UPLOAD,
            InputSourceType.HTTP_JSON_BODY,
            InputSourceType.HTTP_PATH_PARAM
        ]
        
        for source in entry_point.input_sources:
            if source.source_type in risky_input_types:
                factors.append(f"Risky input source: {source.source_type.value}")
        
        # Missing CSRF protection
        if self._is_state_changing_operation(entry_point) and not entry_point.csrf_protection:
            factors.append("CSRF vulnerability potential")
        
        return factors[:5]  # Limit to top 5 factors for readability
    
    def assess_multiple_entry_points(self, entry_points: List[EntryPoint]) -> List[EntryPoint]:
        """
        Assess risk for multiple entry points
        
        Args:
            entry_points: List of entry points to assess
            
        Returns:
            List of entry points with risk assessments
        """
        assessed = []
        
        for entry_point in entry_points:
            assessed_ep = self.assess_risk(entry_point)
            assessed.append(assessed_ep)
        
        # Sort by risk score (highest first)
        assessed.sort(key=lambda ep: (ep.risk_level.value, ep.risk_score), reverse=True)
        
        logger.info(f"Assessed risk for {len(assessed)} entry points")
        return assessed
    
    def get_risk_summary(self, entry_points: List[EntryPoint]) -> Dict[str, Any]:
        """
        Generate risk summary statistics
        
        Args:
            entry_points: List of assessed entry points
            
        Returns:
            Dictionary with risk statistics
        """
        if not entry_points:
            return {
                'total_entry_points': 0,
                'risk_distribution': {},
                'average_score': 0,
                'highest_risk_entry_point': None
            }
        
        risk_counts = {
            RiskLevel.HIGH: 0,
            RiskLevel.MODERATE: 0,
            RiskLevel.LOW: 0
        }
        
        total_score = 0
        highest_risk_ep = None
        highest_score = -1
        
        for ep in entry_points:
            risk_counts[ep.risk_level] += 1
            total_score += ep.risk_score
            
            if ep.risk_score > highest_score:
                highest_score = ep.risk_score
                highest_risk_ep = ep
        
        return {
            'total_entry_points': len(entry_points),
            'risk_distribution': {
                'high': risk_counts[RiskLevel.HIGH],
                'moderate': risk_counts[RiskLevel.MODERATE],
                'low': risk_counts[RiskLevel.LOW]
            },
            'average_score': total_score / len(entry_points),
            'highest_risk_entry_point': {
                'name': highest_risk_ep.function_name if highest_risk_ep else None,
                'score': highest_score,
                'risk_level': highest_risk_ep.risk_level.value if highest_risk_ep else None
            }
        }