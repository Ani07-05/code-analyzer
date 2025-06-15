# src/integrations/stackoverflow_client.py
import requests
import time
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

class StackOverflowAPIClient:
    """Stack Overflow API client for security-focused data acquisition"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://api.stackexchange.com/2.3"
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        
        # Security-related tags we want to collect
        self.security_tags = [
            'security', 'xss', 'sql-injection', 'csrf', 'authentication',
            'authorization', 'vulnerability', 'encryption', 'sanitization',
            'validation', 'injection', 'security-headers', 'https'
        ]
        
        # Rate limiting
        self.requests_per_day = 10000
        self.requests_made = 0
        self.last_request_time = None
        
    def get_security_questions(self, tag: str, max_pages: int = 3) -> List[Dict[str, Any]]:
        """Get security-related questions for a specific tag"""
        questions = []
        
        for page in range(1, max_pages + 1):
            if self.requests_made >= self.requests_per_day:
                self.logger.warning("Daily API limit reached")
                break
                
            try:
                params = {
                    'order': 'desc',
                    'sort': 'votes',
                    'tagged': tag,
                    'site': 'stackoverflow',
                    'page': page,
                    'pagesize': 100,
                    'filter': 'withbody',  # Include question body
                    'min': 3,  # Minimum 3 votes
                }
                
                if self.api_key:
                    params['key'] = self.api_key
                
                # Rate limiting
                if self.last_request_time:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < 0.1:  # 10 requests per second max
                        time.sleep(0.1 - time_since_last)
                
                response = requests.get(f"{self.base_url}/questions", params=params)
                self.last_request_time = time.time()
                self.requests_made += 1
                
                if response.status_code == 200:
                    data = response.json()
                    page_questions = data.get('items', [])
                    questions.extend(page_questions)
                    
                    self.logger.info(f"Retrieved {len(page_questions)} questions for tag '{tag}' (page {page})")
                    
                    # Check if we have more pages
                    if not data.get('has_more', False):
                        break
                        
                elif response.status_code == 429:
                    # Rate limited
                    self.logger.warning("Rate limited, waiting...")
                    time.sleep(60)
                    continue
                else:
                    self.logger.error(f"API error {response.status_code}: {response.text}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error fetching questions for tag '{tag}': {e}")
                break
        
        return questions
    
    def get_question_answers(self, question_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
        """Get answers for specific questions"""
        answers_by_question = {}
        
        # Process in batches of 100 (API limit)
        for i in range(0, len(question_ids), 100):
            batch_ids = question_ids[i:i+100]
            ids_str = ';'.join(map(str, batch_ids))
            
            try:
                params = {
                    'order': 'desc',
                    'sort': 'votes',
                    'site': 'stackoverflow',
                    'filter': 'withbody',
                }
                
                if self.api_key:
                    params['key'] = self.api_key
                
                # Rate limiting
                if self.last_request_time:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < 0.1:
                        time.sleep(0.1 - time_since_last)
                
                response = requests.get(f"{self.base_url}/questions/{ids_str}/answers", params=params)
                self.last_request_time = time.time()
                self.requests_made += 1
                
                if response.status_code == 200:
                    data = response.json()
                    answers = data.get('items', [])
                    
                    # Group answers by question_id
                    for answer in answers:
                        question_id = answer['question_id']
                        if question_id not in answers_by_question:
                            answers_by_question[question_id] = []
                        answers_by_question[question_id].append(answer)
                    
                    self.logger.info(f"Retrieved answers for {len(batch_ids)} questions")
                    
                elif response.status_code == 429:
                    self.logger.warning("Rate limited, waiting...")
                    time.sleep(60)
                    continue
                else:
                    self.logger.error(f"API error {response.status_code}: {response.text}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error fetching answers: {e}")
                break
        
        return answers_by_question
    
    def create_security_dataset(self, output_dir: str = "./knowledge_base/stackoverflow_data") -> Dict[str, Any]:
        """Create a comprehensive security dataset from Stack Overflow"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        dataset_stats = {
            'total_questions': 0,
            'total_answers': 0,
            'tags_processed': [],
            'processing_time': 0,
            'created_at': datetime.now().isoformat()
        }
        
        start_time = time.time()
        all_security_posts = []
        
        self.logger.info("Starting Stack Overflow security dataset creation...")
        
        for tag in self.security_tags:
            self.logger.info(f"Processing tag: {tag}")
            
            # Get questions for this tag (reduced pages for faster testing)
            questions = self.get_security_questions(tag, max_pages=2)  
            
            if not questions:
                continue
            
            # Get question IDs
            question_ids = [q['question_id'] for q in questions]
            
            # Get answers for these questions
            answers_by_question = self.get_question_answers(question_ids)
            
            # Process and format the data
            for question in questions:
                question_id = question['question_id']
                
                # Format the post data
                post_data = {
                    'id': question_id,
                    'title': question['title'],
                    'body': question.get('body', ''),
                    'tags': question.get('tags', []),
                    'score': question.get('score', 0),
                    'view_count': question.get('view_count', 0),
                    'creation_date': question.get('creation_date', 0),
                    'accepted_answer_id': question.get('accepted_answer_id'),
                    'answer_count': question.get('answer_count', 0),
                    'is_answered': question.get('is_answered', False)
                }
                
                # Add the best answer if available
                if question_id in answers_by_question:
                    answers = answers_by_question[question_id]
                    # Sort by votes and get the best answer
                    answers.sort(key=lambda x: x.get('score', 0), reverse=True)
                    if answers:
                        best_answer = answers[0]
                        post_data['accepted_answer'] = best_answer.get('body', '')
                        post_data['accepted_answer_score'] = best_answer.get('score', 0)
                
                all_security_posts.append(post_data)
            
            dataset_stats['tags_processed'].append({
                'tag': tag,
                'questions': len(questions),
                'answers': sum(len(answers_by_question.get(qid, [])) for qid in question_ids)
            })
            
            # Save progress
            self.logger.info(f"Processed {len(questions)} questions for tag '{tag}'")
        
        # Save the complete dataset
        dataset_file = output_path / 'security_posts.jsonl'
        with open(dataset_file, 'w', encoding='utf-8') as f:
            for post in all_security_posts:
                f.write(json.dumps(post, ensure_ascii=False) + '\n')
        
        # Update final stats
        dataset_stats['total_questions'] = len(all_security_posts)
        dataset_stats['total_answers'] = sum(
            1 for post in all_security_posts if post.get('accepted_answer')
        )
        dataset_stats['processing_time'] = time.time() - start_time
        
        # Save metadata
        metadata_file = output_path / 'dataset_metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(dataset_stats, f, indent=2)
        
        self.logger.info(f"Dataset creation complete!")
        self.logger.info(f"Total questions: {dataset_stats['total_questions']}")
        self.logger.info(f"Total answers: {dataset_stats['total_answers']}")
        self.logger.info(f"Processing time: {dataset_stats['processing_time']:.2f} seconds")
        self.logger.info(f"Saved to: {dataset_file}")
        
        return dataset_stats