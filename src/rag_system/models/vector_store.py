# src/rag_system/vector_store.py
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import hashlib
import pickle
from .models.rag_models import SearchQuery, SearchResult, KnowledgeContext

class SecurityKnowledgeStore:
    """ChromaDB-based vector store for security knowledge (RAG Component)"""
    
    def __init__(self, 
                 persist_directory: str = "./knowledge_base/vector_db",
                 embedding_model_name: str = "all-MiniLM-L6-v2",
                 enable_caching: bool = True):
        
        self.logger = logging.getLogger(__name__)
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB with persistence
        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                is_persistent=True
            )
        )
        
        # Initialize embedding model
        self.logger.info(f"Loading embedding model: {embedding_model_name}")
        self.embedding_model = SentenceTransformer(embedding_model_name)
        
        # Enable embedding caching for performance
        self.enable_caching = enable_caching
        self.embedding_cache = {}
        self.cache_file = self.persist_directory / "embedding_cache.pkl"
        self._load_embedding_cache()
        
        # Create collections
        self.collections = {
            'stackoverflow': self._get_or_create_collection('stackoverflow_security'),
            'owasp': self._get_or_create_collection('owasp_guidelines'),
            'vulnerability_patterns': self._get_or_create_collection('vuln_patterns')
        }
        
        self.logger.info("SecurityKnowledgeStore initialized successfully")
    
    def _get_or_create_collection(self, name: str):
        """Get or create a ChromaDB collection"""
        try:
            collection = self.client.get_collection(name)
            self.logger.info(f"Loaded existing collection: {name}")
            return collection
        except ValueError:
            collection = self.client.create_collection(
                name=name,
                embedding_function=None  # We handle embeddings manually
            )
            self.logger.info(f"Created new collection: {name}")
            return collection
    
    def _load_embedding_cache(self):
        """Load embedding cache from disk"""
        if self.enable_caching and self.cache_file.exists():
            try:
                with open(self.cache_file, 'rb') as f:
                    self.embedding_cache = pickle.load(f)
                self.logger.info(f"Loaded {len(self.embedding_cache)} cached embeddings")
            except Exception as e:
                self.logger.warning(f"Failed to load embedding cache: {e}")
                self.embedding_cache = {}
    
    def _save_embedding_cache(self):
        """Save embedding cache to disk"""
        if self.enable_caching:
            try:
                with open(self.cache_file, 'wb') as f:
                    pickle.dump(self.embedding_cache, f)
            except Exception as e:
                self.logger.warning(f"Failed to save embedding cache: {e}")
    
    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding with caching"""
        if self.enable_caching:
            # Create cache key
            cache_key = hashlib.md5(text.encode()).hexdigest()
            
            if cache_key in self.embedding_cache:
                return self.embedding_cache[cache_key]
            
            # Generate embedding
            embedding = self.embedding_model.encode([text])[0].tolist()
            
            # Cache it
            self.embedding_cache[cache_key] = embedding
            
            # Save cache periodically
            if len(self.embedding_cache) % 100 == 0:
                self._save_embedding_cache()
            
            return embedding
        else:
            return self.embedding_model.encode([text])[0].tolist()
    
    def add_stackoverflow_post(self, post_data: Dict[str, Any]) -> bool:
        """Add a Stack Overflow post to the vector store"""
        try:
            # Create searchable text
            text_content = self._create_so_search_text(post_data)
            
            # Generate embedding
            embedding = self._get_embedding(text_content)
            
            # Prepare metadata
            metadata = {
                'post_id': post_data['id'],
                'title': post_data['title'],
                'votes': post_data.get('score', 0),
                'tags': ','.join(post_data.get('tags', [])),
                'has_accepted_answer': bool(post_data.get('accepted_answer_id')),
                'url': f"https://stackoverflow.com/questions/{post_data['id']}",
                'creation_date': post_data.get('creation_date', ''),
                'view_count': post_data.get('view_count', 0)
            }
            
            # Add to collection
            self.collections['stackoverflow'].add(
                embeddings=[embedding],
                documents=[text_content],
                metadatas=[metadata],
                ids=[f"so_{post_data['id']}"]
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add SO post {post_data.get('id', 'unknown')}: {e}")
            return False
    
    def _create_so_search_text(self, post_data: Dict[str, Any]) -> str:
        """Create optimized search text from SO post data"""
        title = post_data.get('title', '')
        body = post_data.get('body', '')
        tags = ' '.join(post_data.get('tags', []))
        accepted_answer = post_data.get('accepted_answer', '')
        
        # Truncate body if too long (embedding models have token limits)
        if len(body) > 1000:
            body = body[:1000] + "..."
            
        if len(accepted_answer) > 500:
            accepted_answer = accepted_answer[:500] + "..."
        
        return f"Title: {title}\nTags: {tags}\nQuestion: {body}\nAnswer: {accepted_answer}"
    
    def add_owasp_guideline(self, guideline_data: Dict[str, Any]) -> bool:
        """Add OWASP guideline to the vector store"""
        try:
            # Create searchable text
            text_content = self._create_owasp_search_text(guideline_data)
            
            # Generate embedding
            embedding = self._get_embedding(text_content)
            
            # Add to collection
            self.collections['owasp'].add(
                embeddings=[embedding],
                documents=[text_content],
                metadatas=[guideline_data.get('metadata', {})],
                ids=[guideline_data['id']]
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add OWASP guideline {guideline_data.get('id', 'unknown')}: {e}")
            return False
    
    def _create_owasp_search_text(self, guideline_data: Dict[str, Any]) -> str:
        """Create optimized search text from OWASP guideline data"""
        title = guideline_data.get('title', '')
        description = guideline_data.get('description', '')
        prevention = guideline_data.get('prevention', '')
        
        if isinstance(prevention, list):
            prevention = ' '.join(prevention)
            
        return f"Title: {title}\nDescription: {description}\nPrevention: {prevention}"
    
    def search_similar_vulnerabilities(self, 
                                     query: SearchQuery,
                                     top_k: int = 5) -> List[SearchResult]:
        """Find similar vulnerabilities with SO citations"""
        
        try:
            # Generate query embedding
            query_embedding = self._get_embedding(query.vulnerability_description)
            
            # Build where clause for filtering
            where_clause = self._build_where_clause(query.filters or {})
            
            # Search in Stack Overflow collection
            results = self.collections['stackoverflow'].query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=where_clause if where_clause else None
            )
            
            # Format results
            search_results = []
            if results['metadatas'] and results['metadatas'][0]:
                for i, metadata in enumerate(results['metadatas'][0]):
                    search_results.append(SearchResult(
                        document_id=f"so_{metadata['post_id']}",
                        content=results['documents'][0][i],
                        metadata=metadata,
                        relevance_score=1 - results['distances'][0][i],  # Convert distance to similarity
                        source_type="stackoverflow"
                    ))
            
            # Sort by relevance score (highest first)
            search_results.sort(key=lambda x: x.relevance_score, reverse=True)
            
            self.logger.info(f"Found {len(search_results)} similar vulnerabilities")
            return search_results
            
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return []
    
    def search_owasp_guidelines(self, 
                               query: SearchQuery,
                               top_k: int = 3) -> List[SearchResult]:
        """Retrieve relevant OWASP guidelines"""
        
        try:
            # Create OWASP-specific query
            owasp_query = f"OWASP {query.vulnerability_type or ''} {query.vulnerability_description} prevention security guideline"
            query_embedding = self._get_embedding(owasp_query)
            
            results = self.collections['owasp'].query(
                query_embeddings=[query_embedding],
                n_results=top_k
            )
            
            search_results = []
            if results['metadatas'] and results['metadatas'][0]:
                for i, metadata in enumerate(results['metadatas'][0]):
                    search_results.append(SearchResult(
                        document_id=metadata.get('id', f"owasp_{i}"),
                        content=results['documents'][0][i],
                        metadata=metadata,
                        relevance_score=1 - results['distances'][0][i],
                        source_type="owasp"
                    ))
            
            search_results.sort(key=lambda x: x.relevance_score, reverse=True)
            
            self.logger.info(f"Found {len(search_results)} OWASP guidelines")
            return search_results
            
        except Exception as e:
            self.logger.error(f"OWASP search failed: {e}")
            return []
    
    def get_knowledge_context(self, 
                             vulnerability_description: str,
                             vulnerability_type: Optional[str] = None,
                             entry_point_context: Optional[Dict[str, Any]] = None) -> KnowledgeContext:
        """Get comprehensive knowledge context for AI agent"""
        
        # Create search query
        query = SearchQuery(
            vulnerability_description=vulnerability_description,
            vulnerability_type=vulnerability_type,
            context=entry_point_context or {}
        )
        
        # Search both knowledge sources
        so_results = self.search_similar_vulnerabilities(query, top_k=5)
        owasp_results = self.search_owasp_guidelines(query, top_k=3)
        
        # Extract risk factors from context
        risk_factors = []
        if entry_point_context:
            risk_factors = entry_point_context.get('risk_factors', [])
        
        return KnowledgeContext(
            stackoverflow_results=so_results,
            owasp_results=owasp_results,
            entry_point_context=entry_point_context or {},
            risk_factors=risk_factors
        )
    
    def _build_where_clause(self, filters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Build ChromaDB where clause from filters"""
        where_clause = {}
        
        if 'vulnerability_type' in filters:
            where_clause["tags"] = {"$contains": filters['vulnerability_type']}
        
        if 'min_votes' in filters:
            where_clause["votes"] = {"$gte": filters['min_votes']}
        
        if 'has_accepted_answer' in filters:
            where_clause["has_accepted_answer"] = {"$eq": filters['has_accepted_answer']}
        
        return where_clause if where_clause else None
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        stats = {}
        
        for name, collection in self.collections.items():
            try:
                count = collection.count()
                stats[name] = {
                    'document_count': count,
                    'status': 'active' if count > 0 else 'empty'
                }
            except Exception as e:
                stats[name] = {
                    'document_count': 0,
                    'status': f'error: {e}'
                }
        
        stats['embedding_cache_size'] = len(self.embedding_cache)
        stats['total_documents'] = sum(s.get('document_count', 0) for s in stats.values() if isinstance(s, dict))
        
        return stats
    
    def validate_citations(self, min_relevance: float = 0.6) -> Dict[str, Any]:
        """Validate quality of stored citations"""
        validation_results = {
            'total_citations': 0,
            'valid_citations': 0,
            'low_relevance_citations': 0,
            'issues': []
        }
        
        try:
            # Get all SO documents
            so_collection = self.collections['stackoverflow']
            results = so_collection.get(include=['metadatas'])
            
            if results['metadatas']:
                validation_results['total_citations'] = len(results['metadatas'])
                
                for metadata in results['metadatas']:
                    votes = metadata.get('votes', 0)
                    has_answer = metadata.get('has_accepted_answer', False)
                    
                    if votes >= 1 and has_answer:
                        validation_results['valid_citations'] += 1
                    else:
                        validation_results['low_relevance_citations'] += 1
                        validation_results['issues'].append(f"Post {metadata.get('post_id')} has low quality")
        
        except Exception as e:
            validation_results['issues'].append(f"Validation error: {e}")
        
        return validation_results
    
    def cleanup(self):
        """Cleanup resources"""
        self._save_embedding_cache()
        self.logger.info("SecurityKnowledgeStore cleanup completed")

# src/rag_system/__init__.py
from .vector_store import SecurityKnowledgeStore
from .models import *

__all__ = ['SecurityKnowledgeStore']