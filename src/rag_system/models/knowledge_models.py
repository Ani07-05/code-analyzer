# src/rag_system/models/knowledge_models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from enum import Enum
import json

class VulnerabilityType(Enum):
    XSS = "cross_site_scripting"
    SQL_INJECTION = "sql_injection"
    CSRF = "csrf"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"

class RiskLevel(Enum):
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"

@dataclass
class StackOverflowCitation:
    """Stack Overflow citation with validation"""
    post_id: int
    title: str
    url: str
    accepted_answer_id: Optional[int] = None
    votes: int = 0
    relevance_score: float = 0.0
    excerpt: str = ""
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.url:
            self.url = f"https://stackoverflow.com/questions/{self.post_id}"
    
    def is_valid(self) -> bool:
        """Validate citation quality"""
        return (
            self.post_id > 0 and
            self.relevance_score >= 0.6 and
            self.votes >= 1 and
            len(self.title) > 10
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'post_id': self.post_id,
            'title': self.title,
            'url': self.url,
            'votes': self.votes,
            'relevance_score': self.relevance_score,
            'excerpt': self.excerpt,
            'tags': self.tags
        }

@dataclass
class OWASPReference:
    """OWASP guideline reference"""
    guideline_type: str  # "top10", "cheat_sheet", "testing_guide"
    title: str
    url: str
    section: str
    recommendation: str
    vulnerability_category: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.guideline_type,
            'title': self.title,
            'url': self.url,
            'section': self.section,
            'recommendation': self.recommendation
        }

@dataclass
class CodeExample:
    """Code example showing vulnerable vs fixed code"""
    language: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    framework: str = "generic"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'language': self.language,
            'vulnerable_code': self.vulnerable_code,
            'fixed_code': self.fixed_code,
            'explanation': self.explanation,
            'framework': self.framework
        }

@dataclass
class AgentReasoning:
    """AI Agent reasoning and decision process"""
    vulnerability_analysis: str
    risk_assessment: str
    fix_strategy: str
    confidence_factors: List[str]
    uncertainty_factors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_analysis': self.vulnerability_analysis,
            'risk_assessment': self.risk_assessment,
            'fix_strategy': self.fix_strategy,
            'confidence_factors': self.confidence_factors,
            'uncertainty_factors': self.uncertainty_factors
        }

@dataclass
class FixSuggestion:
    """Complete fix suggestion with mandatory citations"""
    vulnerability_type: VulnerabilityType
    risk_level: RiskLevel
    entry_point_file: str
    entry_point_line: int
    
    # MANDATORY Stack Overflow Citation
    stackoverflow_citation: StackOverflowCitation
    
    # OWASP Reference  
    owasp_reference: OWASPReference
    
    # AI Agent Analysis
    agent_reasoning: AgentReasoning
    
    # Fix Content
    fix_description: str
    code_examples: List[CodeExample]
    implementation_steps: List[str]
    
    # Metadata
    confidence_score: float
    generated_timestamp: datetime = field(default_factory=datetime.now)
    
    def has_valid_citation(self) -> bool:
        """Validate that fix has proper SO citation (MANDATORY)"""
        return (
            self.stackoverflow_citation is not None and 
            self.stackoverflow_citation.is_valid()
        )
    
    def get_citation_summary(self) -> str:
        """Get formatted citation summary"""
        if not self.has_valid_citation():
            return "❌ No valid Stack Overflow citation"
        
        citation = self.stackoverflow_citation
        return f"✅ SO Citation: [{citation.title}]({citation.url}) - {citation.votes} votes (relevance: {citation.relevance_score:.2f})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'risk_level': self.risk_level.value,
            'entry_point': {
                'file': self.entry_point_file,
                'line': self.entry_point_line
            },
            'stackoverflow_citation': self.stackoverflow_citation.to_dict(),
            'owasp_reference': self.owasp_reference.to_dict(),
            'agent_reasoning': self.agent_reasoning.to_dict(),
            'fix_description': self.fix_description,
            'code_examples': [ex.to_dict() for ex in self.code_examples],
            'implementation_steps': self.implementation_steps,
            'confidence_score': self.confidence_score,
            'generated_timestamp': self.generated_timestamp.isoformat(),
            'citation_valid': self.has_valid_citation()
        }
    
    def to_markdown(self) -> str:
        """Convert to markdown format"""
        md = f"""## {self.risk_level.value} Risk: {self.vulnerability_type.value.replace('_', ' ').title()}

**File**: `{self.entry_point_file}:{self.entry_point_line}`
**Risk Score**: {self.confidence_score:.1f}/100

### 📚 Stack Overflow Citation
{self.get_citation_summary()}

### 🛡️ OWASP Guideline
**{self.owasp_reference.title}**
- Section: {self.owasp_reference.section}
- Recommendation: {self.owasp_reference.recommendation}
- URL: {self.owasp_reference.url}

### 🤖 AI Agent Analysis
**Vulnerability Analysis**: {self.agent_reasoning.vulnerability_analysis}
**Risk Assessment**: {self.agent_reasoning.risk_assessment}
**Fix Strategy**: {self.agent_reasoning.fix_strategy}

### 🔧 Fix Description
{self.fix_description}

### 💻 Code Examples
"""
        
        for i, example in enumerate(self.code_examples, 1):
            md += f"""
#### Example {i}: {example.framework.title()}

**Vulnerable Code:**
```{example.language}
{example.vulnerable_code}
```

**Fixed Code:**
```{example.language}
{example.fixed_code}
```

**Explanation:** {example.explanation}
"""

        md += f"""
### 📋 Implementation Steps
"""
        for i, step in enumerate(self.implementation_steps, 1):
            md += f"{i}. {step}\n"
            
        return md

# src/rag_system/models/rag_models.py
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class SearchQuery:
    """RAG search query structure"""
    vulnerability_description: str
    vulnerability_type: Optional[str] = None
    context: Dict[str, Any] = None
    filters: Dict[str, Any] = None
    
@dataclass
class SearchResult:
    """RAG search result structure"""
    document_id: str
    content: str
    metadata: Dict[str, Any]
    relevance_score: float
    source_type: str  # "stackoverflow", "owasp", "knowledge_base"

@dataclass
class KnowledgeContext:
    """Context for AI agent decision making"""
    stackoverflow_results: List[SearchResult]
    owasp_results: List[SearchResult]
    entry_point_context: Dict[str, Any]
    risk_factors: List[str]
    
    def get_best_so_result(self) -> Optional[SearchResult]:
        """Get best Stack Overflow result by relevance"""
        if not self.stackoverflow_results:
            return None
        return max(self.stackoverflow_results, key=lambda x: x.relevance_score)
    
    def get_best_owasp_result(self) -> Optional[SearchResult]:
        """Get best OWASP result by relevance"""
        if not self.owasp_results:
            return None
        return max(self.owasp_results, key=lambda x: x.relevance_score)

# src/rag_system/models/__init__.py
from .knowledge_models import (
    VulnerabilityType,
    RiskLevel,
    StackOverflowCitation,
    OWASPReference,
    CodeExample,
    AgentReasoning,
    FixSuggestion
)

from .rag_models import (
    SearchQuery,
    SearchResult,
    KnowledgeContext
)

__all__ = [
    'VulnerabilityType',
    'RiskLevel', 
    'StackOverflowCitation',
    'OWASPReference',
    'CodeExample',
    'AgentReasoning',
    'FixSuggestion',
    'SearchQuery',
    'SearchResult',
    'KnowledgeContext'
]