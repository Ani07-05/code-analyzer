"""
AI model interfaces and data structures for Phase 3.
File: src/ai_validation/models/ai_models.py
"""

import time
import asyncio
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

import torch


class ModelSize(Enum):
    """Available model sizes."""
    SMALL = "7b"   # CodeLlama-7B
    MEDIUM = "13b" # CodeLlama-13B  
    LARGE = "34b"  # CodeLlama-34B


class QuantizationType(Enum):
    """Model quantization types."""
    NONE = "none"
    INT8 = "int8"
    INT4 = "int4"


@dataclass
class ModelResponse:
    """Response from AI model generation."""
    text: str
    confidence: float
    generation_time: float
    tokens_generated: int
    finish_reason: str = "length"  # "length", "eos_token", "stop_sequence"
    
    def __post_init__(self):
        """Validate response data."""
        if self.confidence < 0.0 or self.confidence > 1.0:
            self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass 
class CodeLlamaModel:
    """
    CodeLlama model wrapper with generation capabilities.
    
    Provides a unified interface for interacting with CodeLlama models
    regardless of size or quantization configuration.
    """
    size: ModelSize
    quantization: QuantizationType
    model_path: str
    device: str
    memory_usage_mb: float
    tokenizer: Any = None  # AutoTokenizer
    model: Any = None      # AutoModelForCausalLM
    load_time_seconds: float = 0.0
    
    async def generate(self, 
                      prompt: str, 
                      max_tokens: int = 512,
                      temperature: float = 0.1, 
                      stop_tokens: Optional[List[str]] = None,
                      timeout_seconds: float = 30.0) -> ModelResponse:
        """
        Generate response from model.
        
        Args:
            prompt: Input prompt for generation
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0 = deterministic)
            stop_tokens: List of stop sequences
            timeout_seconds: Maximum generation time
            
        Returns:
            ModelResponse with generated text and metadata
            
        Raises:
            TimeoutError: If generation takes too long
            RuntimeError: If model is not properly loaded
        """
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Model not properly loaded")
        
        # Run generation in thread pool to avoid blocking
        try:
            response = await asyncio.wait_for(
                self._generate_sync(prompt, max_tokens, temperature, stop_tokens),
                timeout=timeout_seconds
            )
            return response
        except asyncio.TimeoutError:
            raise TimeoutError(f"Model generation timed out after {timeout_seconds}s")
    
    async def _generate_sync(self, 
                           prompt: str,
                           max_tokens: int,
                           temperature: float,
                           stop_tokens: Optional[List[str]]) -> ModelResponse:
        """Synchronous generation wrapped for async."""
        start_time = time.time()
        
        # Prepare inputs
        inputs = self.tokenizer(
            prompt, 
            return_tensors="pt",
            truncation=True,
            max_length=2048  # Reasonable context length
        ).to(self.device)
        
        input_length = inputs['input_ids'].shape[1]
        
        # Setup generation parameters
        generation_config = {
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": temperature > 0.0,
            "pad_token_id": self.tokenizer.pad_token_id or self.tokenizer.eos_token_id,
            "eos_token_id": self.tokenizer.eos_token_id,
            "use_cache": True,
            "return_dict_in_generate": True,
            "output_scores": True
        }
        
        # Add stop tokens if provided
        if stop_tokens:
            # Convert stop tokens to token IDs
            stop_token_ids = []
            for stop_token in stop_tokens:
                token_ids = self.tokenizer.encode(stop_token, add_special_tokens=False)
                if token_ids:
                    stop_token_ids.extend(token_ids)
            
            if stop_token_ids:
                generation_config["eos_token_id"] = stop_token_ids
        
        # Generate with the model
        with torch.no_grad():
            try:
                outputs = self.model.generate(
                    inputs['input_ids'],
                    attention_mask=inputs.get('attention_mask'),
                    **generation_config
                )
                
                # Extract generated tokens (excluding input)
                generated_tokens = outputs.sequences[0][input_length:]
                generated_text = self.tokenizer.decode(
                    generated_tokens, 
                    skip_special_tokens=True,
                    clean_up_tokenization_spaces=True
                )
                
                # Calculate confidence from scores if available
                confidence = self._calculate_confidence(outputs.scores) if hasattr(outputs, 'scores') else 0.8
                
                # Determine finish reason
                finish_reason = self._determine_finish_reason(
                    generated_tokens, max_tokens, stop_tokens
                )
                
                generation_time = time.time() - start_time
                
                return ModelResponse(
                    text=generated_text.strip(),
                    confidence=confidence,
                    generation_time=generation_time,
                    tokens_generated=len(generated_tokens),
                    finish_reason=finish_reason
                )
                
            except torch.cuda.OutOfMemoryError:
                # Clear cache and try again with smaller max_tokens
                torch.cuda.empty_cache()
                if max_tokens > 256:
                    return await self._generate_sync(
                        prompt, max_tokens // 2, temperature, stop_tokens
                    )
                else:
                    raise RuntimeError("GPU out of memory even with reduced token limit")
    
    def _calculate_confidence(self, scores: List[torch.Tensor]) -> float:
        """
        Calculate confidence score from model output scores.
        
        Args:
            scores: List of score tensors from model generation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not scores:
            return 0.5
        
        try:
            # Calculate average probability of selected tokens
            confidences = []
            
            for score_tensor in scores:
                # Apply softmax to get probabilities
                probs = torch.softmax(score_tensor, dim=-1)
                
                # Get probability of the selected token (highest probability)
                max_prob = torch.max(probs).item()
                confidences.append(max_prob)
            
            # Return average confidence
            avg_confidence = sum(confidences) / len(confidences)
            return min(1.0, max(0.0, avg_confidence))
            
        except Exception:
            # Fallback to default confidence
            return 0.7
    
    def _determine_finish_reason(self, 
                                generated_tokens: torch.Tensor,
                                max_tokens: int,
                                stop_tokens: Optional[List[str]]) -> str:
        """Determine why generation stopped."""
        tokens_generated = len(generated_tokens)
        
        # Check if we hit the token limit
        if tokens_generated >= max_tokens:
            return "length"
        
        # Check if we hit EOS token
        if self.tokenizer.eos_token_id in generated_tokens:
            return "eos_token"
        
        # Check for stop sequences
        if stop_tokens:
            generated_text = self.tokenizer.decode(generated_tokens, skip_special_tokens=True)
            for stop_token in stop_tokens:
                if stop_token in generated_text:
                    return "stop_sequence"
        
        return "length"
    
    async def generate_batch(self, 
                           prompts: List[str],
                           max_tokens: int = 512,
                           temperature: float = 0.1) -> List[ModelResponse]:
        """
        Generate responses for multiple prompts efficiently.
        
        Args:
            prompts: List of input prompts
            max_tokens: Maximum tokens per generation
            temperature: Sampling temperature
            
        Returns:
            List of ModelResponse objects
        """
        if not prompts:
            return []
        
        # For simplicity, process one by one
        # TODO: Implement true batch processing for better efficiency
        responses = []
        
        for prompt in prompts:
            try:
                response = await self.generate(prompt, max_tokens, temperature)
                responses.append(response)
            except Exception as e:
                # Create error response
                responses.append(ModelResponse(
                    text=f"Error generating response: {e}",
                    confidence=0.0,
                    generation_time=0.0,
                    tokens_generated=0,
                    finish_reason="error"
                ))
        
        return responses
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate number of tokens in text."""
        if self.tokenizer is None:
            # Rough estimate: 1 token per 4 characters
            return len(text) // 4
        
        try:
            tokens = self.tokenizer.encode(text, add_special_tokens=False)
            return len(tokens)
        except Exception:
            return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and statistics."""
        info = {
            "size": self.size.value,
            "quantization": self.quantization.value,
            "device": self.device,
            "memory_usage_mb": self.memory_usage_mb,
            "load_time_seconds": self.load_time_seconds,
            "model_path": self.model_path
        }
        
        # Add model-specific details if available
        if self.model is not None and hasattr(self.model, 'config'):
            config = self.model.config
            info.update({
                "vocab_size": getattr(config, 'vocab_size', 'unknown'),
                "hidden_size": getattr(config, 'hidden_size', 'unknown'),
                "num_layers": getattr(config, 'num_hidden_layers', 'unknown'),
                "num_attention_heads": getattr(config, 'num_attention_heads', 'unknown')
            })
        
        return info
    
    def clear_cache(self) -> None:
        """Clear model cache to free memory."""
        if torch.cuda.is_available() and self.device.startswith("cuda"):
            torch.cuda.empty_cache()
    
    def __repr__(self) -> str:
        return (f"CodeLlamaModel(size={self.size.value}, "
                f"quantization={self.quantization.value}, "
                f"device={self.device}, "
                f"memory={self.memory_usage_mb:.1f}MB)")


# Helper functions for model management

def get_model_requirements() -> Dict[ModelSize, Dict[str, float]]:
    """Get memory and disk requirements for each model size."""
    return {
        ModelSize.SMALL: {
            "disk_gb": 13.0,
            "memory_gb_fp16": 14.0,
            "memory_gb_int8": 7.0,
            "memory_gb_int4": 4.0
        },
        ModelSize.MEDIUM: {
            "disk_gb": 26.0,
            "memory_gb_fp16": 26.0,
            "memory_gb_int8": 13.0,
            "memory_gb_int4": 8.0
        },
        ModelSize.LARGE: {
            "disk_gb": 68.0,
            "memory_gb_fp16": 68.0,
            "memory_gb_int8": 34.0,
            "memory_gb_int4": 20.0
        }
    }


def recommend_model_size(available_memory_gb: float, 
                        task_complexity: str = "medium") -> Optional[ModelSize]:
    """
    Recommend optimal model size based on available memory.
    
    Args:
        available_memory_gb: Available memory in GB
        task_complexity: Task complexity level
        
    Returns:
        Recommended model size or None if insufficient memory
    """
    requirements = get_model_requirements()
    
    # Priority order based on task complexity
    if task_complexity == "simple":
        priority = [ModelSize.SMALL, ModelSize.MEDIUM, ModelSize.LARGE]
    elif task_complexity == "complex":
        priority = [ModelSize.LARGE, ModelSize.MEDIUM, ModelSize.SMALL]
    else:  # medium
        priority = [ModelSize.MEDIUM, ModelSize.SMALL, ModelSize.LARGE]
    
    # For small GPU memory (< 6GB), always recommend 7B with hybrid loading
    if available_memory_gb < 6.0:
        return ModelSize.SMALL
    
    # Find largest model that fits in memory (using INT4 quantization)
    for size in priority:
        required_memory = requirements[size]["memory_gb_int4"]
        if available_memory_gb >= required_memory:
            return size
    
    return None


def validate_model_files(model_path: str) -> bool:
    """
    Validate that model directory contains all required files.
    
    Args:
        model_path: Path to model directory
        
    Returns:
        True if model is valid, False otherwise
    """
    from pathlib import Path
    
    model_dir = Path(model_path)
    
    if not model_dir.exists() or not model_dir.is_dir():
        return False
    
    # Required files
    required_files = [
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json"
    ]
    
    for file_name in required_files:
        if not (model_dir / file_name).exists():
            return False
    
    # Check for model weights (either .bin or .safetensors)
    weight_files = (list(model_dir.glob("*.bin")) + 
                   list(model_dir.glob("*.safetensors")))
    
    return len(weight_files) > 0