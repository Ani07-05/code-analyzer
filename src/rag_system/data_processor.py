# src/rag_system/data_processor.py
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import time
from datetime import datetime
from tqdm import tqdm

from .vector_store import SecurityKnowledgeStore

class ProductionDataProcessor:
    """Process and index production security data into RAG system"""
    
    def __init__(self, vector_store: SecurityKnowledgeStore):
        self.vector_store = vector_store
        self.logger = logging.getLogger(__name__)
        
    def process_stackoverflow_dataset(self, data_file: str) -> Dict[str, Any]:
        """Process Stack Overflow dataset and index into vector store"""
        
        data_path = Path(data_file)
        if not data_path.exists():
            raise FileNotFoundError(f"Stack Overflow data file not found: {data_file}")
        
        self.logger.info(f"Processing Stack Overflow dataset: {data_file}")
        
        stats = {
            'total_posts': 0,
            'successful_indexes': 0,
            'failed_indexes': 0,
            'processing_time': 0,
            'average_relevance': 0.0
        }
        
        start_time = time.time()
        successful_posts = []
        
        # Read and process posts
        with open(data_path, 'r', encoding='utf-8') as f:
            posts = [json.loads(line) for line in f if line.strip()]
        
        stats['total_posts'] = len(posts)
        self.logger.info(f"Found {len(posts)} posts to process")
        
        # Process posts in batches for better performance
        batch_size = 50
        for i in tqdm(range(0, len(posts), batch_size), desc="Processing SO posts"):
            batch = posts[i:i+batch_size]
            
            for post in batch:
                try:
                    # Filter for quality posts
                    if self._is_quality_post(post):
                        success = self.vector_store.add_stackoverflow_post(post)
                        if success:
                            stats['successful_indexes'] += 1
                            successful_posts.append(post)
                        else:
                            stats['failed_indexes'] += 1
                    else:
                        stats['failed_indexes'] += 1
                        
                except Exception as e:
                    self.logger.warning(f"Failed to process post {post.get('id', 'unknown')}: {e}")
                    stats['failed_indexes'] += 1
            
            # Periodic progress logging
            if (i // batch_size) % 10 == 0:
                self.logger.info(f"Processed {i + len(batch)} posts ({stats['successful_indexes']} successful)")
        
        stats['processing_time'] = time.time() - start_time
        
        # Calculate average relevance (this would require testing queries)
        if successful_posts:
            stats['average_relevance'] = self._estimate_dataset_quality(successful_posts[:20])
        
        self.logger.info(f"Stack Overflow processing complete:")
        self.logger.info(f"  Total posts: {stats['total_posts']}")
        self.logger.info(f"  Successfully indexed: {stats['successful_indexes']}")
        self.logger.info(f"  Failed: {stats['failed_indexes']}")
        self.logger.info(f"  Processing time: {stats['processing_time']:.2f} seconds")
        self.logger.info(f"  Success rate: {stats['successful_indexes']/max(stats['total_posts'], 1)*100:.1f}%")
        
        return stats
    
    def process_owasp_guidelines(self, guidelines_dir: str) -> Dict[str, Any]:
        """Process OWASP guidelines and index into vector store"""
        
        guidelines_path = Path(guidelines_dir)
        if not guidelines_path.exists():
            raise FileNotFoundError(f"OWASP guidelines directory not found: {guidelines_dir}")
        
        self.logger.info(f"Processing OWASP guidelines from: {guidelines_dir}")
        
        stats = {
            'total_guidelines': 0,
            'successful_indexes': 0,
            'failed_indexes': 0,
            'processing_time': 0
        }
        
        start_time = time.time()
        
        # Process cheat sheets
        cheat_sheets_file = guidelines_path / 'cheat_sheets.jsonl'
        if cheat_sheets_file.exists():
            stats_cs = self._process_guidelines_file(cheat_sheets_file, 'cheat_sheet')
            stats['total_guidelines'] += stats_cs['total']
            stats['successful_indexes'] += stats_cs['successful']
            stats['failed_indexes'] += stats_cs['failed']
        
        # Process Top 10
        top10_file = guidelines_path / 'top10_2021.jsonl'
        if top10_file.exists():
            stats_t10 = self._process_guidelines_file(top10_file, 'top10')
            stats['total_guidelines'] += stats_t10['total']
            stats['successful_indexes'] += stats_t10['successful']
            stats['failed_indexes'] += stats_t10['failed']
        
        stats['processing_time'] = time.time() - start_time
        
        self.logger.info(f"OWASP processing complete:")
        self.logger.info(f"  Total guidelines: {stats['total_guidelines']}")
        self.logger.info(f"  Successfully indexed: {stats['successful_indexes']}")
        self.logger.info(f"  Failed: {stats['failed_indexes']}")
        self.logger.info(f"  Processing time: {stats['processing_time']:.2f} seconds")
        
        return stats
    
    def _process_guidelines_file(self, file_path: Path, guideline_type: str) -> Dict[str, int]:
        """Process a single OWASP guidelines file"""
        stats = {'total': 0, 'successful': 0, 'failed': 0}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            guidelines = [json.loads(line) for line in f if line.strip()]
        
        stats['total'] = len(guidelines)
        
        for guideline in guidelines:
            try:
                # Convert to format expected by vector store
                guideline_data = {
                    'id': guideline['id'],
                    'title': guideline['title'],
                    'description': guideline.get('content', ''),
                    'prevention': guideline.get('content', ''),
                    'metadata': {
                        'type': guideline_type,
                        'title': guideline['title'],
                        'url': guideline.get('url', ''),
                        'section': 'prevention',
                        **guideline.get('metadata', {})
                    }
                }
                
                success = self.vector_store.add_owasp_guideline(guideline_data)
                if success:
                    stats['successful'] += 1
                else:
                    stats['failed'] += 1
                    
            except Exception as e:
                self.logger.warning(f"Failed to process guideline {guideline.get('id', 'unknown')}: {e}")
                stats['failed'] += 1
        
        return stats
    
    def _is_quality_post(self, post: Dict[str, Any]) -> bool:
        """Determine if a Stack Overflow post is high quality"""
        
        # Quality criteria
        min_votes = 2
        min_title_length = 10
        min_body_length = 50
        
        # Check basic quality metrics
        score = post.get('score', 0)
        title = post.get('title', '')
        body = post.get('body', '')
        
        if score < min_votes:
            return False
            
        if len(title) < min_title_length:
            return False
            
        if len(body) < min_body_length:
            return False
        
        # Prefer posts with answers
        has_answer = post.get('accepted_answer') or post.get('answer_count', 0) > 0
        
        # Bonus for security-specific content
        security_indicators = ['security', 'vulnerability', 'attack', 'injection', 'xss', 'csrf']
        content = (title + ' ' + body).lower()
        has_security_content = any(indicator in content for indicator in security_indicators)
        
        return has_answer and has_security_content
    
    def _estimate_dataset_quality(self, sample_posts: List[Dict[str, Any]]) -> float:
        """Estimate average relevance quality of dataset"""
        
        if not sample_posts:
            return 0.0
        
        try:
            from .models.rag_models import SearchQuery
            
            # Test with a few sample queries
            test_queries = [
                "XSS vulnerability Flask prevention",
                "SQL injection parameterized queries",
                "CSRF token authentication"
            ]
            
            total_relevance = 0.0
            query_count = 0
            
            for query_text in test_queries:
                query = SearchQuery(vulnerability_description=query_text)
                results = self.vector_store.search_similar_vulnerabilities(query, top_k=3)
                
                if results:
                    avg_relevance = sum(r.relevance_score for r in results) / len(results)
                    total_relevance += avg_relevance
                    query_count += 1
            
            return total_relevance / query_count if query_count > 0 else 0.0
            
        except Exception as e:
            self.logger.warning(f"Could not estimate dataset quality: {e}")
            return 0.0
    
    def create_production_dataset(self, force_download: bool = False) -> Dict[str, Any]:
        """Create complete production dataset from Stack Overflow API and OWASP"""
        
        self.logger.info("🚀 Creating production security dataset...")
        
        overall_stats = {
            'creation_time': datetime.now().isoformat(),
            'stackoverflow': {},
            'owasp': {},
            'total_processing_time': 0
        }
        
        start_time = time.time()
        
        # Step 1: Download Stack Overflow data
        so_data_file = Path("./knowledge_base/stackoverflow_data/security_posts.jsonl")
        
        if force_download or not so_data_file.exists():
            self.logger.info("📊 Downloading Stack Overflow security data...")
            try:
                from ..integrations.stackoverflow_client import StackOverflowAPIClient
                so_client = StackOverflowAPIClient()
                so_stats = so_client.create_security_dataset()
                overall_stats['stackoverflow']['download'] = so_stats
            except Exception as e:
                self.logger.error(f"Failed to download SO data: {e}")
                overall_stats['stackoverflow']['download'] = {'error': str(e)}
        else:
            self.logger.info("📊 Using existing Stack Overflow data...")
        
        # Step 2: Process Stack Overflow data
        if so_data_file.exists():
            self.logger.info("🔄 Processing Stack Overflow data...")
            so_process_stats = self.process_stackoverflow_dataset(str(so_data_file))
            overall_stats['stackoverflow']['processing'] = so_process_stats
        
        # Step 3: Download OWASP guidelines
        owasp_dir = Path("./knowledge_base/owasp_guidelines")
        
        if force_download or not any(owasp_dir.glob("*.jsonl")):
            self.logger.info("🛡️ Downloading OWASP guidelines...")
            try:
                from ..integrations.owasp_client import OWASPGuidelinesClient
                owasp_client = OWASPGuidelinesClient()
                owasp_client.download_owasp_cheat_sheets()
                owasp_client.create_owasp_top10_guidelines()
            except Exception as e:
                self.logger.error(f"Failed to download OWASP data: {e}")
        else:
            self.logger.info("🛡️ Using existing OWASP guidelines...")
        
        # Step 4: Process OWASP guidelines
        if owasp_dir.exists():
            self.logger.info("🔄 Processing OWASP guidelines...")
            owasp_process_stats = self.process_owasp_guidelines(str(owasp_dir))
            overall_stats['owasp']['processing'] = owasp_process_stats
        
        # Final statistics
        overall_stats['total_processing_time'] = time.time() - start_time
        
        # Get final vector store statistics
        vs_stats = self.vector_store.get_collection_stats()
        overall_stats['final_vector_store_stats'] = vs_stats
        
        self.logger.info("🎉 Production dataset creation complete!")
        self.logger.info(f"📊 Total processing time: {overall_stats['total_processing_time']:.2f} seconds")
        self.logger.info(f"📈 Vector store statistics: {vs_stats}")
        
        # Save overall statistics
        stats_file = Path("./knowledge_base/production_dataset_stats.json")
        with open(stats_file, 'w') as f:
            json.dump(overall_stats, f, indent=2)
        
        return overall_stats