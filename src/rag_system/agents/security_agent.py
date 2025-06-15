# src/rag_system/agents/security_agent.py
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from ..models.knowledge_models import (
    VulnerabilityType, RiskLevel, StackOverflowCitation, 
    OWASPReference, CodeExample, AgentReasoning, FixSuggestion
)
from ..models.rag_models import KnowledgeContext, SearchResult
from ..vector_store import SecurityKnowledgeStore
from entry_detector.models import EntryPoint

class SecurityFixAgent:
    """AI Agent for intelligent security fix generation (AI Agent Component)"""
    
    def __init__(self, vector_store: SecurityKnowledgeStore):
        self.vector_store = vector_store
        self.logger = logging.getLogger(__name__)
        
        # Vulnerability type mapping from entry points
        self.vulnerability_mapping = {
            'form_input': VulnerabilityType.XSS,
            'sql_query': VulnerabilityType.SQL_INJECTION,
            'file_upload': VulnerabilityType.FILE_UPLOAD,
            'authentication': VulnerabilityType.AUTHENTICATION,
            'admin_access': VulnerabilityType.AUTHORIZATION,
            'command_execution': VulnerabilityType.COMMAND_INJECTION,
            'csrf_token': VulnerabilityType.CSRF,
            'access_control': VulnerabilityType.BROKEN_ACCESS_CONTROL
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            'HIGH': 80,
            'MODERATE': 40,
            'LOW': 0
        }
        
        self.logger.info("SecurityFixAgent initialized")
    
    def analyze_and_fix(self, entry_point: EntryPoint, risk_score: int) -> Optional[FixSuggestion]:
        """Main agent method: analyze vulnerability and generate fix with mandatory citations"""
        
        self.logger.info(f"Analyzing vulnerability at {entry_point.file_path}:{entry_point.line_start}")
        
        # Step 1: Intelligent vulnerability analysis
        vuln_analysis = self._analyze_vulnerability(entry_point, risk_score)
        if not vuln_analysis:
            self.logger.warning("Could not analyze vulnerability - skipping")
            return None
        
        vulnerability_type, vulnerability_description, agent_reasoning = vuln_analysis
        
        # Step 2: RAG knowledge retrieval
        knowledge_context = self._retrieve_knowledge(
            vulnerability_description, 
            vulnerability_type.value,
            entry_point
        )
        
        # Step 3: Citation validation (MANDATORY)
        so_citation = self._extract_stackoverflow_citation(knowledge_context)
        if not so_citation or not so_citation.is_valid():
            self.logger.error("No valid Stack Overflow citation found - cannot generate fix")
            return None
        
        # Step 4: OWASP reference extraction
        owasp_reference = self._extract_owasp_reference(knowledge_context, vulnerability_type)
        
        # Step 5: AI-generated fix synthesis
        fix_content = self._synthesize_fix(
            entry_point, vulnerability_type, knowledge_context, agent_reasoning
        )
        
        # Step 6: Calculate confidence score
        confidence_score = self._calculate_confidence(
            knowledge_context, so_citation, owasp_reference, risk_score
        )
        
        # Step 7: Create comprehensive fix suggestion
        fix_suggestion = FixSuggestion(
            vulnerability_type=vulnerability_type,
            risk_level=self._determine_risk_level(risk_score),
            entry_point_file=entry_point.file_path,
            entry_point_line=entry_point.line_start,
            stackoverflow_citation=so_citation,
            owasp_reference=owasp_reference,
            agent_reasoning=agent_reasoning,
            fix_description=fix_content['description'],
            code_examples=fix_content['code_examples'],
            implementation_steps=fix_content['implementation_steps'],
            confidence_score=confidence_score
        )
        
        # Final validation
        if not fix_suggestion.has_valid_citation():
            self.logger.error("Generated fix failed citation validation")
            return None
        
        self.logger.info(f"✅ Fix generated with valid SO citation: {so_citation.url}")
        return fix_suggestion
    
    def _analyze_vulnerability(self, entry_point: EntryPoint, risk_score: int) -> Optional[Tuple[VulnerabilityType, str, AgentReasoning]]:
        """Intelligent vulnerability analysis using AI reasoning"""
        
        # Determine vulnerability type from entry point risk factors
        vulnerability_type = self._determine_vulnerability_type(entry_point)
        if not vulnerability_type:
            return None
        
        # Create vulnerability description for RAG search
        vulnerability_description = self._create_vulnerability_description(entry_point, vulnerability_type)
        
        # AI Agent reasoning process
        agent_reasoning = self._perform_agent_reasoning(entry_point, vulnerability_type, risk_score)
        
        return vulnerability_type, vulnerability_description, agent_reasoning
    
    def _determine_vulnerability_type(self, entry_point: EntryPoint) -> Optional[VulnerabilityType]:
        """AI agent logic to determine vulnerability type"""
        
        risk_factors = set(entry_point.risk_factors)
        
        # Priority-based vulnerability classification
        if 'sql_injection' in risk_factors or 'database_query' in risk_factors:
            return VulnerabilityType.SQL_INJECTION
        
        elif 'command_execution' in risk_factors or 'os_command' in risk_factors:
            return VulnerabilityType.COMMAND_INJECTION
        
        elif 'file_upload' in risk_factors:
            return VulnerabilityType.FILE_UPLOAD
        
        elif 'admin_access' in risk_factors or 'privileged_operation' in risk_factors:
            return VulnerabilityType.AUTHORIZATION
        
        elif 'authentication' in risk_factors or 'login' in risk_factors:
            return VulnerabilityType.AUTHENTICATION
        
        elif 'csrf' in risk_factors or 'state_changing' in risk_factors:
            return VulnerabilityType.CSRF
        
        elif 'user_input' in risk_factors or 'form_input' in risk_factors:
            return VulnerabilityType.XSS
        
        elif 'access_control' in risk_factors:
            return VulnerabilityType.BROKEN_ACCESS_CONTROL
        
        # Default to XSS for unspecified user input
        if risk_factors:
            return VulnerabilityType.XSS
        
        return None
    
    def _create_vulnerability_description(self, entry_point: EntryPoint, vuln_type: VulnerabilityType) -> str:
        """Create optimized description for RAG search"""
        
        base_descriptions = {
            VulnerabilityType.XSS: "cross-site scripting XSS vulnerability user input sanitization escaping",
            VulnerabilityType.SQL_INJECTION: "SQL injection parameterized queries prepared statements database security",
            VulnerabilityType.FILE_UPLOAD: "file upload vulnerability validation sanitization malicious files",
            VulnerabilityType.AUTHENTICATION: "authentication bypass security login session management",
            VulnerabilityType.AUTHORIZATION: "authorization access control privilege escalation admin access",
            VulnerabilityType.COMMAND_INJECTION: "command injection OS command execution shell security",
            VulnerabilityType.CSRF: "CSRF cross-site request forgery token protection state changing",
            VulnerabilityType.BROKEN_ACCESS_CONTROL: "broken access control security authorization"
        }
        
        description = base_descriptions.get(vuln_type, "security vulnerability")
        
        # Add context from entry point
        if entry_point.framework:
            description += f" {entry_point.framework}"
        
        # Add specific risk factors
        context_factors = [factor for factor in entry_point.risk_factors if factor not in vuln_type.value]
        if context_factors:
            description += f" {' '.join(context_factors[:3])}"  # Limit context
        
        return description
    
    def _perform_agent_reasoning(self, entry_point: EntryPoint, vuln_type: VulnerabilityType, risk_score: int) -> AgentReasoning:
        """AI agent reasoning and analysis"""
        
        # Vulnerability analysis
        vulnerability_analysis = f"Detected {vuln_type.value.replace('_', ' ')} vulnerability in {entry_point.framework or 'application'} at {entry_point.file_path}:{entry_point.line_start}. Risk factors include: {', '.join(entry_point.risk_factors[:5])}."
        
        # Risk assessment
        risk_level = self._determine_risk_level(risk_score)
        risk_assessment = f"Risk level: {risk_level.value} ({risk_score}/100). "
        
        if risk_score >= 80:
            risk_assessment += "Critical business impact potential. Immediate remediation required."
        elif risk_score >= 40:
            risk_assessment += "Moderate security risk. Should be addressed in next security sprint."
        else:
            risk_assessment += "Low priority security improvement. Address when convenient."
        
        # Fix strategy
        fix_strategies = {
            VulnerabilityType.XSS: "Implement input validation and output escaping using framework security features",
            VulnerabilityType.SQL_INJECTION: "Replace string concatenation with parameterized queries or ORM",
            VulnerabilityType.FILE_UPLOAD: "Add file type validation, size limits, and secure storage",
            VulnerabilityType.AUTHENTICATION: "Implement proper authentication mechanisms and session management",
            VulnerabilityType.AUTHORIZATION: "Add access control checks and role-based permissions",
            VulnerabilityType.COMMAND_INJECTION: "Avoid OS command execution or use safe alternatives",
            VulnerabilityType.CSRF: "Implement CSRF tokens and verify on state-changing operations",
            VulnerabilityType.BROKEN_ACCESS_CONTROL: "Implement proper authorization checks"
        }
        
        fix_strategy = fix_strategies.get(vuln_type, "Apply security best practices")
        
        # Confidence and uncertainty factors
        confidence_factors = [
            f"Clear {vuln_type.value} pattern detected",
            f"Framework context available: {entry_point.framework or 'generic'}",
            f"Risk score: {risk_score}/100"
        ]
        
        uncertainty_factors = []
        if risk_score < 50:
            uncertainty_factors.append("Lower risk score may indicate false positive")
        if not entry_point.framework:
            uncertainty_factors.append("Framework not detected - generic fixes provided")
        if len(entry_point.risk_factors) < 2:
            uncertainty_factors.append("Limited risk factor context")
        
        return AgentReasoning(
            vulnerability_analysis=vulnerability_analysis,
            risk_assessment=risk_assessment,
            fix_strategy=fix_strategy,
            confidence_factors=confidence_factors,
            uncertainty_factors=uncertainty_factors
        )
    
    def _retrieve_knowledge(self, vulnerability_description: str, vulnerability_type: str, entry_point: EntryPoint) -> KnowledgeContext:
        """Retrieve knowledge using RAG system"""
        
        # Prepare entry point context for RAG
        entry_point_context = {
            'file_path': entry_point.file_path,
            'line_number': entry_point.line_start,
            'framework': entry_point.framework,
            'risk_factors': entry_point.risk_factors,
            'route_info': getattr(entry_point, 'route_info', {}),
            'input_sources': getattr(entry_point, 'input_sources', [])
        }
        
        # Get comprehensive knowledge context
        knowledge_context = self.vector_store.get_knowledge_context(
            vulnerability_description=vulnerability_description,
            vulnerability_type=vulnerability_type,
            entry_point_context=entry_point_context
        )
        
        self.logger.info(f"Retrieved {len(knowledge_context.stackoverflow_results)} SO results, {len(knowledge_context.owasp_results)} OWASP results")
        
        return knowledge_context
    
    def _extract_stackoverflow_citation(self, knowledge_context: KnowledgeContext) -> Optional[StackOverflowCitation]:
        """Extract and validate Stack Overflow citation (MANDATORY)"""
        
        best_result = knowledge_context.get_best_so_result()
        if not best_result:
            self.logger.error("No Stack Overflow results found")
            return None
        
        # Extract citation data
        metadata = best_result.metadata
        
        citation = StackOverflowCitation(
            post_id=metadata['post_id'],
            title=metadata['title'],
            url=metadata['url'],
            accepted_answer_id=None,  # Would need API call to get this
            votes=metadata.get('votes', 0),
            relevance_score=best_result.relevance_score,
            excerpt=best_result.content[:200] + "..." if len(best_result.content) > 200 else best_result.content,
            tags=metadata.get('tags', '').split(',') if metadata.get('tags') else []
        )
        
        # Validate citation quality
        if not citation.is_valid():
            self.logger.warning(f"Stack Overflow citation quality too low: relevance={citation.relevance_score:.2f}, votes={citation.votes}")
            return None
        
        return citation
    
    def _extract_owasp_reference(self, knowledge_context: KnowledgeContext, vuln_type: VulnerabilityType) -> OWASPReference:
        """Extract OWASP reference"""
        
        best_owasp = knowledge_context.get_best_owasp_result()
        
        if best_owasp:
            metadata = best_owasp.metadata
            return OWASPReference(
                guideline_type=metadata.get('type', 'guideline'),
                title=metadata.get('title', f'OWASP {vuln_type.value.replace("_", " ").title()} Prevention'),
                url=metadata.get('url', 'https://owasp.org/'),
                section=metadata.get('section', 'Prevention'),
                recommendation=best_owasp.content[:300] + "..." if len(best_owasp.content) > 300 else best_owasp.content,
                vulnerability_category=vuln_type.value
            )
        else:
            # Fallback OWASP reference
            return self._create_fallback_owasp_reference(vuln_type)
    
    def _create_fallback_owasp_reference(self, vuln_type: VulnerabilityType) -> OWASPReference:
        """Create fallback OWASP reference when none found"""
        
        fallback_references = {
            VulnerabilityType.XSS: {
                'title': 'OWASP Cross Site Scripting Prevention Cheat Sheet',
                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                'recommendation': 'Validate all input and encode all output. Use Content Security Policy (CSP) headers.'
            },
            VulnerabilityType.SQL_INJECTION: {
                'title': 'OWASP SQL Injection Prevention Cheat Sheet',
                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                'recommendation': 'Use parameterized queries, stored procedures, or ORM. Validate all input.'
            }
        }
        
        ref_data = fallback_references.get(vuln_type, {
            'title': f'OWASP {vuln_type.value.replace("_", " ").title()} Prevention',
            'url': 'https://owasp.org/www-project-top-ten/',
            'recommendation': 'Follow OWASP security guidelines and best practices.'
        })
        
        return OWASPReference(
            guideline_type='cheat_sheet',
            title=ref_data['title'],
            url=ref_data['url'],
            section='Prevention',
            recommendation=ref_data['recommendation'],
            vulnerability_category=vuln_type.value
        )
    
    def _synthesize_fix(self, entry_point: EntryPoint, vuln_type: VulnerabilityType, 
                       knowledge_context: KnowledgeContext, agent_reasoning: AgentReasoning) -> Dict[str, Any]:
        """AI synthesis of fix content"""
        
        # Generate fix description
        fix_description = self._generate_fix_description(vuln_type, knowledge_context, agent_reasoning)
        
        # Generate code examples
        code_examples = self._generate_code_examples(entry_point, vuln_type)
        
        # Generate implementation steps
        implementation_steps = self._generate_implementation_steps(vuln_type, entry_point.framework)
        
        return {
            'description': fix_description,
            'code_examples': code_examples,
            'implementation_steps': implementation_steps
        }
    
    def _generate_fix_description(self, vuln_type: VulnerabilityType, 
                                knowledge_context: KnowledgeContext, 
                                agent_reasoning: AgentReasoning) -> str:
        """Generate comprehensive fix description"""
        
        # Base fix descriptions
        base_fixes = {
            VulnerabilityType.XSS: "To prevent Cross-Site Scripting (XSS) attacks, implement proper input validation and output encoding. Use your framework's built-in escaping mechanisms and Content Security Policy (CSP) headers.",
            
            VulnerabilityType.SQL_INJECTION: "To prevent SQL Injection attacks, replace string concatenation with parameterized queries or prepared statements. Use ORM frameworks when possible and validate all input data.",
            
            VulnerabilityType.FILE_UPLOAD: "To secure file uploads, implement strict file type validation, size limits, and store uploaded files outside the web root. Scan files for malware and use secure naming conventions."
        }
        
        base_description = base_fixes.get(vuln_type, f"To fix this {vuln_type.value.replace('_', ' ')} vulnerability, implement appropriate security controls and follow security best practices.")
        
        # Add context from Stack Overflow citation if available
        if knowledge_context.stackoverflow_results:
            best_so = knowledge_context.get_best_so_result()
            if best_so and best_so.relevance_score > 0.7:
                base_description += f" Based on community knowledge, {best_so.content[:100]}..."
        
        return base_description
    
    def _generate_code_examples(self, entry_point: EntryPoint, vuln_type: VulnerabilityType) -> List[CodeExample]:
        """Generate framework-specific code examples"""
        
        framework = entry_point.framework or 'python'
        
        if vuln_type == VulnerabilityType.XSS:
            return self._get_xss_examples(framework)
        elif vuln_type == VulnerabilityType.SQL_INJECTION:
            return self._get_sql_injection_examples(framework)
        elif vuln_type == VulnerabilityType.FILE_UPLOAD:
            return self._get_file_upload_examples(framework)
        
        return []
    
    def _get_xss_examples(self, framework: str) -> List[CodeExample]:
        """Get XSS prevention examples"""
        if framework.lower() == 'flask':
            return [CodeExample(
                language="python",
                vulnerable_code="""# Vulnerable: Direct user input rendering
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Results for: {query}</h1>" """,
                fixed_code="""# Fixed: Proper escaping with Jinja2
@app.route('/search')  
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)

# search.html template
<h1>Results for: {{ query|e }}</h1>""",
                explanation="Use Jinja2's automatic escaping (|e filter) to prevent XSS attacks",
                framework="flask"
            )]
        
        return [CodeExample(
            language="python",
            vulnerable_code="# Vulnerable: Unescaped user input\noutput = f'<div>{user_input}</div>'",
            fixed_code="# Fixed: Escaped user input\nimport html\noutput = f'<div>{html.escape(user_input)}</div>'",
            explanation="Always escape user input before rendering in HTML",
            framework="generic"
        )]
    
    def _get_sql_injection_examples(self, framework: str) -> List[CodeExample]:
        """Get SQL injection prevention examples"""
        return [CodeExample(
            language="python",
            vulnerable_code="""# Vulnerable: String concatenation
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)""",
            fixed_code="""# Fixed: Parameterized query
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (user_input,))""",
            explanation="Use parameterized queries to prevent SQL injection",
            framework=framework
        )]
    
    def _get_file_upload_examples(self, framework: str) -> List[CodeExample]:
        """Get file upload security examples"""
        return [CodeExample(
            language="python",
            vulnerable_code="""# Vulnerable: No validation
file = request.files['upload']
file.save(f'uploads/{file.filename}')""",
            fixed_code="""# Fixed: Validation and secure storage
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

file = request.files['upload']
if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))""",
            explanation="Validate file types and use secure filename handling",
            framework=framework
        )]
    
    def _generate_implementation_steps(self, vuln_type: VulnerabilityType, framework: Optional[str]) -> List[str]:
        """Generate step-by-step implementation guide"""
        
        step_templates = {
            VulnerabilityType.XSS: [
                "Review all user input handling in templates and views",
                "Enable automatic escaping in template engine",
                "Add Content Security Policy (CSP) headers",
                "Validate and sanitize all user input",
                "Test with XSS payloads to verify protection"
            ],
            VulnerabilityType.SQL_INJECTION: [
                "Identify all database queries using string concatenation",
                "Replace with parameterized queries or ORM methods",
                "Add input validation for all parameters",
                "Use principle of least privilege for database connections",
                "Test with SQL injection payloads"
            ],
            VulnerabilityType.FILE_UPLOAD: [
                "Define allowed file types and size limits",
                "Implement file type validation (not just extension)",
                "Store uploaded files outside web root",
                "Use secure filename generation",
                "Add malware scanning if handling untrusted files"
            ]
        }
        
        steps = step_templates.get(vuln_type, [
            f"Analyze the {vuln_type.value.replace('_', ' ')} vulnerability",
            "Implement appropriate security controls",
            "Test the fix thoroughly",
            "Document the security improvement"
        ])
        
        # Add framework-specific steps
        if framework and framework.lower() == 'flask':
            if vuln_type == VulnerabilityType.XSS:
                steps.append("Consider using Flask-Talisman for automatic security headers")
        
        return steps
    
    def _determine_risk_level(self, risk_score: int) -> RiskLevel:
        """Determine risk level from score"""
        if risk_score >= self.risk_thresholds['HIGH']:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds['MODERATE']:
            return RiskLevel.MODERATE
        else:
            return RiskLevel.LOW
    
    def _calculate_confidence(self, knowledge_context: KnowledgeContext, 
                            so_citation: StackOverflowCitation,
                            owasp_reference: OWASPReference,
                            risk_score: int) -> float:
        """Calculate confidence score for the fix"""
        
        confidence = 0.0
        
        # Stack Overflow citation quality (40% weight)
        if so_citation and so_citation.is_valid():
            citation_score = min(1.0, (so_citation.relevance_score * 0.7 + 
                                     min(so_citation.votes / 20, 1.0) * 0.3))
            confidence += citation_score * 0.4
        
        # OWASP reference availability (30% weight)
        if owasp_reference:
            confidence += 0.3
        
        # Risk score confidence (20% weight)
        risk_confidence = min(risk_score / 100, 1.0)
        confidence += risk_confidence * 0.2
        
        # Knowledge context quality (10% weight)
        if len(knowledge_context.stackoverflow_results) > 0:
            confidence += 0.1
        
        return min(confidence * 100, 100.0)  # Convert to percentage

# src/rag_system/agents/__init__.py
from .security_agent import SecurityFixAgent

__all__ = ['SecurityFixAgent']