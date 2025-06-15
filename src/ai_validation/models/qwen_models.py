"""
Qwen2.5-Coder Models for Security Analysis
Optimized for RTX 3050 and similar hardware
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import time

@dataclass
class QwenModelConfig:
    """Configuration for Qwen models"""
    model_name: str
    model_size_gb: float
    min_vram_gb: float
    recommended_vram_gb: float
    max_tokens: int
    temperature: float = 0.1

class QwenSecurityAnalyzer:
    """Qwen2.5-Coder specialized for security analysis"""
    
    # Available Qwen models for different hardware tiers
    MODELS = {
        "qwen2.5-coder-1.5b": QwenModelConfig(
            model_name="Qwen/Qwen2.5-Coder-1.5B-Instruct",
            model_size_gb=3.1,
            min_vram_gb=2.0,
            recommended_vram_gb=3.5,
            max_tokens=1024,
            temperature=0.1
        ),
        "qwen2.5-coder-7b": QwenModelConfig(
            model_name="Qwen/Qwen2.5-Coder-7B-Instruct", 
            model_size_gb=14.0,
            min_vram_gb=6.0,
            recommended_vram_gb=8.0,
            max_tokens=2048,
            temperature=0.1
        ),
        "qwen2.5-coder-32b": QwenModelConfig(
            model_name="Qwen/Qwen2.5-Coder-32B-Instruct",
            model_size_gb=64.0,
            min_vram_gb=20.0,
            recommended_vram_gb=32.0,
            max_tokens=4096,
            temperature=0.1
        )
    }
    
    def __init__(self, model_size: str = "qwen2.5-coder-1.5b"):
        """Initialize Qwen model for security analysis"""
        self.config = self.MODELS[model_size]
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.load_time = 0.0
        
    def check_hardware_compatibility(self) -> Dict[str, Any]:
        """Check if hardware can run this model"""
        if not torch.cuda.is_available():
            return {
                "compatible": True,
                "device": "cpu",
                "warning": "GPU not available, will use CPU (slower)"
            }
        
        total_vram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        free_vram = (torch.cuda.get_device_properties(0).total_memory - torch.cuda.memory_allocated(0)) / (1024**3)
        
        if free_vram < self.config.min_vram_gb:
            return {
                "compatible": False,
                "device": "none",
                "error": f"Insufficient VRAM: {free_vram:.1f}GB available, {self.config.min_vram_gb}GB required"
            }
        elif free_vram < self.config.recommended_vram_gb:
            return {
                "compatible": True,
                "device": "cuda",
                "warning": f"Limited VRAM: {free_vram:.1f}GB available, {self.config.recommended_vram_gb}GB recommended"
            }
        else:
            return {
                "compatible": True,
                "device": "cuda",
                "optimal": True
            }
    
    async def load_model(self) -> bool:
        """Load the Qwen model"""
        hardware_check = self.check_hardware_compatibility()
        
        if not hardware_check["compatible"]:
            raise RuntimeError(hardware_check["error"])
        
        print(f"Loading {self.config.model_name}...")
        start_time = time.time()
        
        try:
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
            
            # Load model with appropriate settings
            if self.device == "cuda":
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_name,
                    torch_dtype=torch.float16,
                    device_map="auto"
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_name,
                    torch_dtype=torch.float32
                )
                self.model.to(self.device)
            
            self.load_time = time.time() - start_time
            print(f"Model loaded in {self.load_time:.2f}s on {self.device}")
            
            return True
            
        except Exception as e:
            raise RuntimeError(f"Failed to load Qwen model: {e}")
    
    async def analyze_vulnerability(self, code: str, vulnerability_type: str = "GENERAL") -> Dict[str, Any]:
        """Analyze code for security vulnerabilities"""
        if not self.model or not self.tokenizer:
            await self.load_model()
        
        # Create security analysis prompt
        prompt = self._create_security_prompt(code, vulnerability_type)
        
        # Tokenize input
        inputs = self.tokenizer(prompt, return_tensors="pt", max_length=self.config.max_tokens, truncation=True)
        if self.device == "cuda":
            inputs = {k: v.cuda() for k, v in inputs.items()}
        
        # Generate analysis
        start_time = time.time()
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=300,
                temperature=self.config.temperature,
                do_sample=True,
                eos_token_id=self.tokenizer.eos_token_id,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        inference_time = time.time() - start_time
        
        # Decode response
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        analysis = response[len(prompt):].strip()
        
        # Parse the analysis
        return self._parse_security_analysis(analysis, inference_time)
    
    def _create_security_prompt(self, code: str, vulnerability_type: str) -> str:
        """Create optimized prompt for security analysis"""
        return f"""<|im_start|>system
You are a cybersecurity expert specialized in code vulnerability analysis. Analyze the provided code and identify security issues with high precision.

Focus on these vulnerability types:
- SQL Injection
- Cross-Site Scripting (XSS)  
- Path Traversal
- Command Injection
- Authentication/Authorization issues
- Input validation problems

Provide clear, actionable analysis.
<|im_end|>
<|im_start|>user
Analyze this code for security vulnerabilities:

```
{code}
```

Expected vulnerability type: {vulnerability_type}

Provide analysis in this format:
1. VULNERABILITY DETECTED: [YES/NO]
2. VULNERABILITY TYPE: [specific type]
3. CONFIDENCE: [0-100%]
4. EXPLANATION: [detailed explanation]
5. RISK LEVEL: [HIGH/MEDIUM/LOW]
<|im_end|>
<|im_start|>assistant
"""
    
    def _parse_security_analysis(self, analysis: str, inference_time: float) -> Dict[str, Any]:
        """Parse the model's security analysis response"""
        result = {
            "inference_time": inference_time,
            "raw_response": analysis,
            "is_vulnerable": False,
            "vulnerability_type": "NONE",
            "confidence": 0.0,
            "risk_level": "LOW",
            "explanation": analysis
        }
        
        analysis_lower = analysis.lower()
        
        # Check if vulnerability detected
        if ("vulnerability detected: yes" in analysis_lower or 
            "vulnerable" in analysis_lower or
            "security issue" in analysis_lower or
            "injection" in analysis_lower or
            "xss" in analysis_lower):
            result["is_vulnerable"] = True
        
        # Extract vulnerability type
        if "sql injection" in analysis_lower:
            result["vulnerability_type"] = "SQL_INJECTION"
        elif "xss" in analysis_lower or "cross-site scripting" in analysis_lower:
            result["vulnerability_type"] = "XSS"
        elif "path traversal" in analysis_lower:
            result["vulnerability_type"] = "PATH_TRAVERSAL"
        elif "command injection" in analysis_lower:
            result["vulnerability_type"] = "COMMAND_INJECTION"
        elif "authentication" in analysis_lower:
            result["vulnerability_type"] = "AUTHENTICATION"
        
        # Extract confidence (look for percentage)
        import re
        confidence_match = re.search(r'confidence[:\s]*(\d+)%?', analysis_lower)
        if confidence_match:
            result["confidence"] = float(confidence_match.group(1)) / 100.0
        else:
            # Estimate confidence based on response quality
            if result["is_vulnerable"] and len(analysis) > 100:
                result["confidence"] = 0.8
            elif result["is_vulnerable"]:
                result["confidence"] = 0.6
            else:
                result["confidence"] = 0.4
        
        # Extract risk level
        if "high" in analysis_lower and "risk" in analysis_lower:
            result["risk_level"] = "HIGH"
        elif "medium" in analysis_lower and "risk" in analysis_lower:
            result["risk_level"] = "MEDIUM"
        elif result["is_vulnerable"]:
            result["risk_level"] = "MEDIUM"  # Default for vulnerabilities
        
        return result
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model"""
        return {
            "model_name": self.config.model_name,
            "model_size_gb": self.config.model_size_gb,
            "device": self.device,
            "load_time": self.load_time,
            "max_tokens": self.config.max_tokens,
            "vram_usage": torch.cuda.memory_allocated(0) / (1024**3) if torch.cuda.is_available() else 0
        }