"""
AI Model Management for Phase 3 - Complete Implementation
File: src/ai_validation/managers/model_manager.py
"""

import os
import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import torch
import psutil
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

from ..models.ai_models import CodeLlamaModel, ModelSize, QuantizationType, ModelResponse


class ModelLoadingError(Exception):
    """Error loading AI model."""
    pass


class MemoryExhaustedError(Exception):
    """Insufficient memory for AI processing."""
    pass


@dataclass
class SystemResources:
    """System resource information."""
    gpu_available: bool
    gpu_count: int
    gpu_memory_gb: List[float]
    cpu_memory_gb: float
    available_disk_gb: float


class ModelManager:
    """
    Central controller for CodeLlama models with intelligent resource management.
    
    Features:
    - Lazy loading with memory optimization
    - GPU/CPU automatic selection  
    - Model quantization management
    - Fallback strategies for resource constraints
    """
    
    def __init__(self, 
                 gpu_memory_limit: float = 0.8,
                 enable_quantization: bool = True,
                 default_model_size: ModelSize = ModelSize.MEDIUM):
        """
        Initialize ModelManager.
        
        Args:
            gpu_memory_limit: Maximum GPU memory usage (0.0-1.0)
            enable_quantization: Whether to use model quantization
            default_model_size: Default model size to use
        """
        self.gpu_memory_limit = gpu_memory_limit
        self.enable_quantization = enable_quantization
        self.default_model_size = default_model_size
        self.loaded_models: Dict[ModelSize, CodeLlamaModel] = {}
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Detect system resources
        self.system_resources = self._detect_system_resources()
        self.device = self._detect_optimal_device()
        
        # Load configuration
        self.config = self._load_model_config()
        
        self.logger.info(f"ModelManager initialized with device: {self.device}")
        self.logger.info(f"System resources: {self.system_resources}")
    
    def _detect_system_resources(self) -> SystemResources:
        """Detect available system resources."""
        # GPU detection
        gpu_available = torch.cuda.is_available()
        gpu_count = torch.cuda.device_count() if gpu_available else 0
        gpu_memory_gb = []
        
        if gpu_available:
            for i in range(gpu_count):
                props = torch.cuda.get_device_properties(i)
                memory_gb = props.total_memory / (1024**3)
                gpu_memory_gb.append(memory_gb)
                self.logger.info(f"GPU {i}: {props.name} ({memory_gb:.1f}GB)")
        
        # CPU memory
        cpu_memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Available disk space
        available_disk_gb = psutil.disk_usage('.').free / (1024**3)
        
        return SystemResources(
            gpu_available=gpu_available,
            gpu_count=gpu_count,
            gpu_memory_gb=gpu_memory_gb,
            cpu_memory_gb=cpu_memory_gb,
            available_disk_gb=available_disk_gb
        )
    
    def _detect_optimal_device(self) -> str:
        """Detect best available device (GPU/CPU)."""
        if not self.system_resources.gpu_available:
            self.logger.info("No GPU available, using CPU")
            return "cpu"
        
        # Select GPU with most memory
        best_gpu_idx = 0
        best_memory = 0.0
        
        for i, memory_gb in enumerate(self.system_resources.gpu_memory_gb):
            if memory_gb > best_memory:
                best_memory = memory_gb
                best_gpu_idx = i
        
        device = f"cuda:{best_gpu_idx}"
        self.logger.info(f"Selected device: {device} ({best_memory:.1f}GB)")
        return device
    
    def _load_model_config(self) -> Dict[str, Any]:
        """Load model configuration from file."""
        config_path = Path("config/ai_validation/validation_config.json")
        
        if not config_path.exists():
            self.logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._get_default_config()
        
        try:
            with open(config_path) as f:
                config = json.load(f)
            self.logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "models": {
                "default_model_size": "13b",
                "quantization_enabled": True,
                "quantization_type": "int4",
                "max_gpu_memory_percent": 85.0,
                "model_cache_size_gb": 20.0
            },
            "validation": {
                "min_confidence_threshold": 0.7,
                "max_concurrent_validations": 3
            },
            "performance": {
                "batch_optimization": True,
                "enable_predictive_loading": True
            }
        }
    
    async def get_model(self, 
                       size: ModelSize = None,
                       task_complexity: str = "medium") -> CodeLlamaModel:
        """
        Get model with intelligent selection based on task complexity and resources.
        
        Args:
            size: Explicit model size (overrides intelligent selection)
            task_complexity: "simple", "medium", "complex"
            
        Returns:
            Loaded and optimized CodeLlama model
            
        Raises:
            ModelLoadingError: If model loading fails
            MemoryExhaustedError: If insufficient memory
        """
        try:
            if size is None:
                size = self._select_optimal_model_size(task_complexity)
            
            self.logger.info(f"Requesting model: {size.value} for {task_complexity} task")
            
            # Check if model is already loaded
            if size in self.loaded_models:
                self.logger.info(f"Model {size.value} already loaded, returning from cache")
                return self.loaded_models[size]
            
            # Load new model
            model = await self._load_model(size)
            self.loaded_models[size] = model
            
            self.logger.info(f"Model {size.value} loaded successfully")
            return model
            
        except Exception as e:
            self.logger.error(f"Error getting model {size}: {e}")
            
            # Try fallback to smaller model
            if size != ModelSize.SMALL:
                self.logger.info("Attempting fallback to smaller model")
                return await self.get_model(ModelSize.SMALL, task_complexity)
            
            raise ModelLoadingError(f"All model loading attempts failed: {e}")
    
    def _select_optimal_model_size(self, task_complexity: str) -> ModelSize:
        """Intelligent model size selection based on task and resources."""
        complexity_requirements = {
            "simple": ModelSize.SMALL,    # 7B model
            "medium": ModelSize.MEDIUM,   # 13B model  
            "complex": ModelSize.LARGE    # 34B model
        }
        
        desired_size = complexity_requirements.get(task_complexity, ModelSize.MEDIUM)
        
        # Check what models are actually available and can fit in memory
        available_models = []
        for size in [ModelSize.SMALL, ModelSize.MEDIUM, ModelSize.LARGE]:
            if (self._check_model_exists(size) and 
                self._check_memory_availability(size)):
                available_models.append(size)
        
        if not available_models:
            raise ModelLoadingError("No models available or insufficient memory")
        
        # Return best available model that doesn't exceed desired complexity
        size_priority = {ModelSize.SMALL: 1, ModelSize.MEDIUM: 2, ModelSize.LARGE: 3}
        desired_priority = size_priority[desired_size]
        
        for size in [ModelSize.LARGE, ModelSize.MEDIUM, ModelSize.SMALL]:
            if (size in available_models and 
                size_priority[size] <= desired_priority):
                return size
        
        # Fallback to smallest available
        return min(available_models, key=lambda x: size_priority[x])
    
    def _check_model_exists(self, size: ModelSize) -> bool:
        """Check if model files exist locally."""
        model_path = Path(f"models/codellama-{size.value}")
        
        if not model_path.exists():
            self.logger.warning(f"Model directory not found: {model_path}")
            return False
        
        # Check for essential files
        required_files = ["config.json", "tokenizer.json"]
        for file_name in required_files:
            if not (model_path / file_name).exists():
                self.logger.warning(f"Missing model file: {model_path / file_name}")
                return False
        
        # Check for model weights
        weight_files = (list(model_path.glob("*.bin")) + 
                       list(model_path.glob("*.safetensors")))
        
        if not weight_files:
            self.logger.warning(f"No model weight files found in {model_path}")
            return False
        
        return True
    
    def _check_memory_availability(self, size: ModelSize) -> bool:
        """Check if sufficient memory is available for model loading."""
        memory_requirements = {
            ModelSize.SMALL: 3.0,   # 3GB for 7B quantized (was 4.0)
            ModelSize.MEDIUM: 6.0,  # 6GB for 13B quantized (was 8.0) 
            ModelSize.LARGE: 16.0   # 16GB for 34B quantized (was 20.0)
        }
        
        required_gb = memory_requirements[size]
        
        if self.device.startswith("cuda"):
            # GPU memory check
            gpu_id = int(self.device.split(":")[1])
            
            if gpu_id < len(self.system_resources.gpu_memory_gb):
                available_gb = self.system_resources.gpu_memory_gb[gpu_id]
                # Account for current GPU usage
                if torch.cuda.is_available():
                    torch.cuda.set_device(gpu_id)
                    allocated_gb = torch.cuda.memory_allocated(gpu_id) / (1024**3)
                    available_gb -= allocated_gb
                
                return available_gb >= required_gb
        
        # CPU memory check
        available_gb = psutil.virtual_memory().available / (1024**3)
        return available_gb >= required_gb
    
    async def _load_model(self, size: ModelSize) -> CodeLlamaModel:
        """Load model with quantization and optimization."""
        model_path = Path(f"models/codellama-{size.value}")
        
        if not self._check_model_exists(size):
            raise FileNotFoundError(f"Model not found or incomplete: {model_path}")
        
        # Check memory before loading
        if not self._check_memory_availability(size):
            raise MemoryExhaustedError(f"Insufficient memory for {size.value} model")
        
        self.logger.info(f"Loading model from {model_path}")
        start_time = time.time()
        
        try:
            # Setup quantization if enabled
            quantization_config = None
            quant_type = QuantizationType.NONE
            
            if self.enable_quantization:
                quant_type = QuantizationType.INT4  # Default to INT4
                quantization_config = self._get_quantization_config(quant_type)
                self.logger.info(f"Using quantization: {quant_type.value}")
            
            # Load tokenizer
            self.logger.info("Loading tokenizer...")
            tokenizer = AutoTokenizer.from_pretrained(
                str(model_path),
                trust_remote_code=False,
                local_files_only=True
            )
            
            # Ensure pad token exists
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            # Load model with intelligent device mapping
            self.logger.info("Loading model...")
            
            # Configure device map for small GPU memory
            device_map = None
            if self.device.startswith("cuda"):
                # For small GPU memory (< 6GB), use hybrid CPU+GPU
                gpu_memory_gb = self._get_gpu_memory_gb()
                if gpu_memory_gb < 6.0:
                    device_map = self._create_hybrid_device_map(gpu_memory_gb)
                    self.logger.info(f"Using hybrid CPU+GPU device map for {gpu_memory_gb:.1f}GB GPU")
                else:
                    device_map = "auto"
            
            # Enhanced quantization config for small GPU
            if quantization_config and self.device.startswith("cuda"):
                gpu_memory_gb = self._get_gpu_memory_gb()
                if gpu_memory_gb < 6.0:
                    # Enable CPU offloading for small GPU
                    quantization_config.llm_int8_enable_fp32_cpu_offload = True
            
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                quantization_config=quantization_config,
                device_map=device_map,
                torch_dtype=torch.float16 if self.device.startswith("cuda") else torch.float32,
                trust_remote_code=False,
                local_files_only=True,
                low_cpu_mem_usage=True,
                max_memory=self._get_max_memory_config() if device_map else None
            )
            
            # Move to device if not using device_map
            if not self.device.startswith("cuda") or quantization_config is None:
                model = model.to(self.device)
            
            load_time = time.time() - start_time
            memory_usage = self._estimate_model_memory_usage(model)
            
            self.logger.info(f"Model loaded in {load_time:.1f}s, using {memory_usage:.1f}MB")
            
            # Create CodeLlamaModel wrapper
            return CodeLlamaModel(
                size=size,
                quantization=quant_type,
                model_path=str(model_path),
                device=self.device,
                memory_usage_mb=memory_usage,
                tokenizer=tokenizer,
                model=model,
                load_time_seconds=load_time
            )
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise ModelLoadingError(f"Failed to load {size.value} model: {e}")
    
    def _get_quantization_config(self, quant_type: QuantizationType) -> Optional[BitsAndBytesConfig]:
        """Get quantization configuration."""
        if quant_type == QuantizationType.INT4:
            return BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",  # NormalFloat4 for better quality
                llm_int8_enable_fp32_cpu_offload=True  # Enable CPU offloading
            )
        elif quant_type == QuantizationType.INT8:
            return BitsAndBytesConfig(
                load_in_8bit=True,
                int8_threshold=6.0,
                int8_skip_modules=["lm_head"],  # Skip quantizing output layer
                llm_int8_enable_fp32_cpu_offload=True  # Enable CPU offloading
            )
        
        return None
    
    def _estimate_model_memory_usage(self, model) -> float:
        """Estimate model memory usage in MB."""
        try:
            if hasattr(model, 'get_memory_footprint'):
                return model.get_memory_footprint() / (1024**2)
            
            # Fallback: estimate from parameters
            total_params = sum(p.numel() for p in model.parameters())
            
            # Estimate bytes per parameter (depends on quantization)
            if hasattr(model, 'config') and hasattr(model.config, 'quantization_config'):
                if model.config.quantization_config:
                    bytes_per_param = 1  # INT8/INT4 quantized
                else:
                    bytes_per_param = 2  # FP16
            else:
                bytes_per_param = 2  # Default FP16
            
            total_bytes = total_params * bytes_per_param
            return total_bytes / (1024**2)  # Convert to MB
            
        except Exception as e:
            self.logger.warning(f"Could not estimate memory usage: {e}")
            return 0.0
    
    def get_loaded_models(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently loaded models."""
        info = {}
        
        for size, model in self.loaded_models.items():
            info[size.value] = {
                "model_path": model.model_path,
                "device": model.device,
                "memory_usage_mb": model.memory_usage_mb,
                "load_time_seconds": model.load_time_seconds,
                "quantization": model.quantization.value
            }
        
        return info
    
    def clear_model_cache(self, size: ModelSize = None) -> None:
        """Clear model cache to free memory."""
        if size is None:
            # Clear all models
            for model_size in list(self.loaded_models.keys()):
                self._unload_model(model_size)
            self.logger.info("Cleared all models from cache")
        else:
            # Clear specific model
            if size in self.loaded_models:
                self._unload_model(size)
                self.logger.info(f"Cleared {size.value} model from cache")
    
    def _unload_model(self, size: ModelSize) -> None:
        """Unload specific model and free memory."""
        if size in self.loaded_models:
            model = self.loaded_models[size]
            
            # Safely delete model references (avoid meta tensor issues)
            if hasattr(model, 'model'):
                try:
                    # Only move to CPU if not on meta device
                    if hasattr(model.model, 'device') and str(model.model.device) != 'meta':
                        model.model.cpu()
                except Exception as e:
                    self.logger.warning(f"Could not move model to CPU: {e}")
                
                del model.model
                
            if hasattr(model, 'tokenizer'):
                del model.tokenizer
            
            del self.loaded_models[size]
            
            # Force garbage collection and CUDA cache clearing
            import gc
            gc.collect()
            
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
    

    def _get_gpu_memory_gb(self) -> float:
        """Get GPU memory in GB."""
        if not torch.cuda.is_available():
            return 0.0
        
        gpu_id = 0
        if self.device.startswith("cuda:"):
            gpu_id = int(self.device.split(":")[1])
        
        props = torch.cuda.get_device_properties(gpu_id)
        return props.total_memory / (1024**3)
    
    def _create_hybrid_device_map(self, gpu_memory_gb: float) -> dict:
        """Create hybrid CPU+GPU device map for small GPU memory."""
        # For RTX 3050 Laptop (3.7GB), put most layers on GPU, some on CPU
        if gpu_memory_gb <= 4.0:
            return {
                # Put embedding and first layers on GPU
                "model.embed_tokens": 0,
                "model.layers.0": 0,
                "model.layers.1": 0,
                "model.layers.2": 0,
                "model.layers.3": 0,
                "model.layers.4": 0,
                "model.layers.5": 0,
                "model.layers.6": 0,
                "model.layers.7": 0,
                "model.layers.8": 0,
                "model.layers.9": 0,
                "model.layers.10": 0,
                "model.layers.11": 0,
                "model.layers.12": 0,
                "model.layers.13": 0,
                "model.layers.14": 0,
                "model.layers.15": 0,
                "model.layers.16": 0,
                "model.layers.17": 0,
                "model.layers.18": 0,
                "model.layers.19": 0,
                "model.layers.20": 0,
                "model.layers.21": 0,
                "model.layers.22": 0,
                "model.layers.23": 0,
                # Put later layers on CPU to save GPU memory
                "model.layers.24": "cpu",
                "model.layers.25": "cpu", 
                "model.layers.26": "cpu",
                "model.layers.27": "cpu",
                "model.layers.28": "cpu",
                "model.layers.29": "cpu",
                "model.layers.30": "cpu",
                "model.layers.31": "cpu",
                "model.norm": "cpu",
                "lm_head": "cpu"
            }
        else:
            # For larger GPUs, use auto mapping
            return "auto"
    
    def _get_max_memory_config(self) -> dict:
        """Get memory configuration for hybrid loading."""
        if not torch.cuda.is_available():
            return None
        
        gpu_memory_gb = self._get_gpu_memory_gb()
        cpu_memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Reserve some memory for other processes
        gpu_memory_mb = int((gpu_memory_gb * 0.85) * 1024)  # 85% of GPU
        cpu_memory_mb = int((cpu_memory_gb * 0.5) * 1024)   # 50% of CPU
        
        return {
            0: f"{gpu_memory_mb}MB",  # GPU 0
            "cpu": f"{cpu_memory_mb}MB"  # CPU
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and resource usage."""
        status = {
            "device": self.device,
            "loaded_models": len(self.loaded_models),
            "system_resources": {
                "gpu_available": self.system_resources.gpu_available,
                "gpu_count": self.system_resources.gpu_count,
                "cpu_memory_gb": self.system_resources.cpu_memory_gb,
                "available_disk_gb": self.system_resources.available_disk_gb
            }
        }
        
        # Current memory usage
        if self.system_resources.gpu_available:
            gpu_memory = []
            for i in range(self.system_resources.gpu_count):
                if torch.cuda.is_available():
                    torch.cuda.set_device(i)
                    allocated = torch.cuda.memory_allocated(i) / (1024**3)
                    total = torch.cuda.get_device_properties(i).total_memory / (1024**3)
                    gpu_memory.append({
                        "allocated_gb": allocated,
                        "total_gb": total,
                        "usage_percent": (allocated / total) * 100
                    })
            status["gpu_memory"] = gpu_memory
        
        # CPU memory
        memory = psutil.virtual_memory()
        status["cpu_memory"] = {
            "used_gb": memory.used / (1024**3),
            "total_gb": memory.total / (1024**3),
            "usage_percent": memory.percent
        }
        
        return status