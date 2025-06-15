# src/rag_system/models/rag_models.py
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class SearchQuery:
    """RAG search query structure"""
    vulnerability_description: str
    vulnerability_type: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    filters: Optional[Dict[str, Any]] = None
    
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
    stackoverflow_results: List[SearchResult] = field(default_factory=list)
    owasp_results: List[SearchResult] = field(default_factory=list)
    entry_point_context: Dict[str, Any] = field(default_factory=dict)
    risk_factors: List[str] = field(default_factory=list)
    
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