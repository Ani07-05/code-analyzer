# src/integrations/owasp_client.py
import requests
import json
import logging
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime

class OWASPGuidelinesClient:
    """Client for downloading and processing OWASP guidelines"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_urls = {
            'cheat_sheets': 'https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets',
            'top10': 'https://owasp.org/www-project-top-ten'
        }
    
    def download_owasp_cheat_sheets(self, output_dir: str = "./knowledge_base/owasp_guidelines") -> List[Dict[str, Any]]:
        """Download key OWASP cheat sheets"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Key cheat sheets for security
        cheat_sheets = [
            'Cross_Site_Scripting_Prevention_Cheat_Sheet.md',
            'SQL_Injection_Prevention_Cheat_Sheet.md', 
            'Authentication_Cheat_Sheet.md',
            'Authorization_Cheat_Sheet.md',
            'Input_Validation_Cheat_Sheet.md',
            'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md',
            'File_Upload_Cheat_Sheet.md',
            'Session_Management_Cheat_Sheet.md'
        ]
        
        guidelines = []
        
        for sheet_name in cheat_sheets:
            try:
                url = f"{self.base_urls['cheat_sheets']}/{sheet_name}"
                response = requests.get(url)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Parse the markdown content
                    guideline = {
                        'id': f"owasp_{sheet_name.replace('.md', '').lower()}",
                        'title': sheet_name.replace('_', ' ').replace('.md', ''),
                        'type': 'cheat_sheet',
                        'url': f"https://cheatsheetseries.owasp.org/cheatsheets/{sheet_name.replace('.md', '.html')}",
                        'content': content,
                        'metadata': {
                            'source': 'owasp_cheat_sheets',
                            'category': self._categorize_cheat_sheet(sheet_name),
                            'download_date': datetime.now().isoformat()
                        }
                    }
                    
                    guidelines.append(guideline)
                    self.logger.info(f"Downloaded: {sheet_name}")
                    
                else:
                    self.logger.warning(f"Failed to download {sheet_name}: {response.status_code}")
                    
            except Exception as e:
                self.logger.error(f"Error downloading {sheet_name}: {e}")
        
        # Save guidelines
        guidelines_file = output_path / 'cheat_sheets.jsonl'
        with open(guidelines_file, 'w', encoding='utf-8') as f:
            for guideline in guidelines:
                f.write(json.dumps(guideline, ensure_ascii=False) + '\n')
        
        self.logger.info(f"Downloaded {len(guidelines)} OWASP cheat sheets")
        return guidelines
    
    def _categorize_cheat_sheet(self, sheet_name: str) -> str:
        """Categorize cheat sheet by vulnerability type"""
        if 'xss' in sheet_name.lower() or 'cross_site_scripting' in sheet_name.lower():
            return 'xss'
        elif 'sql' in sheet_name.lower():
            return 'sql_injection' 
        elif 'csrf' in sheet_name.lower():
            return 'csrf'
        elif 'auth' in sheet_name.lower():
            return 'authentication'
        elif 'upload' in sheet_name.lower():
            return 'file_upload'
        else:
            return 'general'
    
    def create_owasp_top10_guidelines(self, output_dir: str = "./knowledge_base/owasp_guidelines") -> List[Dict[str, Any]]:
        """Create OWASP Top 10 2021 guidelines"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # OWASP Top 10 2021 data
        top10_2021 = [
            {
                'id': 'owasp_top10_a01',
                'rank': 'A01:2021',
                'title': 'Broken Access Control',
                'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
                'prevention': [
                    'Implement access control mechanisms server-side',
                    'Deny by default except for public resources',
                    'Implement access control checks consistently',
                    'Disable web server directory listing',
                    'Log access control failures and alert admins when appropriate'
                ],
                'category': 'authorization'
            },
            {
                'id': 'owasp_top10_a03',
                'rank': 'A03:2021',
                'title': 'Injection',
                'description': 'An application is vulnerable when user-supplied data is not validated, filtered, or sanitized.',
                'prevention': [
                    'Use parameterized queries or prepared statements',
                    'Validate input using positive server-side validation',
                    'Escape special characters using output encoding',
                    'Use LIMIT and other SQL controls in queries'
                ],
                'category': 'injection'
            },
            {
                'id': 'owasp_top10_a07',
                'rank': 'A07:2021', 
                'title': 'Identification and Authentication Failures',
                'description': 'Confirmation of user identity, authentication, and session management is critical.',
                'prevention': [
                    'Implement multi-factor authentication',
                    'Do not ship or deploy with default credentials',
                    'Implement weak password checks',
                    'Use server-side, secure session managers'
                ],
                'category': 'authentication'
            },
            {
                'id': 'owasp_top10_a04',
                'rank': 'A04:2021',
                'title': 'Insecure Design',
                'description': 'Insecure design is a broad category representing different weaknesses in design and architectural flaws.',
                'prevention': [
                    'Establish a secure development lifecycle',
                    'Use threat modeling for critical authentication, access control, business logic',
                    'Integrate security language and controls into user stories',
                    'Segregate tier layers on the system and network layers'
                ],
                'category': 'design'
            },
            {
                'id': 'owasp_top10_a05',
                'rank': 'A05:2021',
                'title': 'Security Misconfiguration',
                'description': 'Security misconfiguration is commonly a result of insecure default configurations.',
                'prevention': [
                    'Implement a repeatable hardening process',
                    'Remove or do not install unused features and frameworks',
                    'Review and update configurations with security notes, updates, and patches',
                    'Use automated processes to verify effectiveness of configurations'
                ],
                'category': 'configuration'
            }
        ]
        
        guidelines = []
        for item in top10_2021:
            guideline = {
                'id': item['id'],
                'title': f"OWASP {item['rank']} - {item['title']}",
                'type': 'top10',
                'url': f"https://owasp.org/Top10/A{item['rank'].split(':')[0][1:]}_2021-{item['title'].replace(' ', '_')}/",
                'content': f"Description: {item['description']}\n\nPrevention:\n" + '\n'.join(f"- {p}" for p in item['prevention']),
                'metadata': {
                    'rank': item['rank'],
                    'category': item['category'],
                    'source': 'owasp_top10_2021'
                }
            }
            guidelines.append(guideline)
        
        # Save Top 10 guidelines
        top10_file = output_path / 'top10_2021.jsonl'
        with open(top10_file, 'w', encoding='utf-8') as f:
            for guideline in guidelines:
                f.write(json.dumps(guideline, ensure_ascii=False) + '\n')
        
        self.logger.info(f"Created {len(guidelines)} OWASP Top 10 guidelines")
        return guidelines