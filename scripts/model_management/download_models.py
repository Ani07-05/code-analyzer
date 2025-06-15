#!/usr/bin/env python3
"""Download and setup Qwen2.5-Coder models for security analysis."""

import os
import sys
import torch
from pathlib import Path

def download_models():
    """Download Qwen2.5-Coder models based on hardware capabilities."""
    print("[DOWNLOAD] Qwen2.5-Coder models...")
    
    # Detect hardware capabilities
    gpu_available = torch.cuda.is_available()
    vram_gb = 0
    
    if gpu_available:
        vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"[DETECTED] GPU: {torch.cuda.get_device_name(0)} ({vram_gb:.1f}GB VRAM)")
    else:
        print("[DETECTED] No GPU, using CPU mode")
    
    # Select appropriate models based on hardware
    models = []
    
    if vram_gb >= 20:  # High-end hardware
        models = [
            ("Qwen/Qwen2.5-Coder-1.5B-Instruct", "Lightweight model"),
            ("Qwen/Qwen2.5-Coder-7B-Instruct", "Standard model"),
            ("Qwen/Qwen2.5-Coder-32B-Instruct", "High-performance model")
        ]
        print("[STRATEGY] Installing all models for high-end hardware")
    elif vram_gb >= 6:  # Mid-range hardware
        models = [
            ("Qwen/Qwen2.5-Coder-1.5B-Instruct", "Lightweight model"),
            ("Qwen/Qwen2.5-Coder-7B-Instruct", "Standard model")
        ]
        print("[STRATEGY] Installing lightweight and standard models")
    else:  # Low-end hardware or CPU-only
        models = [
            ("Qwen/Qwen2.5-Coder-1.5B-Instruct", "Optimized for your hardware")
        ]
        print("[STRATEGY] Installing only lightweight model for optimal performance")
    
    print(f"[INFO] Will pre-cache {len(models)} model(s) for offline use")
    print("[INFO] Note: Models can also be downloaded automatically on first use")
    
    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM
        
        for model_id, description in models:
            print(f"\\n[DOWNLOADING] {model_id} ({description})...")
            print(f"[INFO] This may take several minutes depending on your internet speed")
            
            # Download tokenizer
            print(f"[STEP] Downloading tokenizer...")
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            
            # Download model
            print(f"[STEP] Downloading model weights...")
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=torch.float16 if gpu_available else torch.float32,
                low_cpu_mem_usage=True,
                device_map="cpu"  # Download to CPU first
            )
            
            print(f"[SUCCESS] {model_id} cached successfully")
            
            # Free memory
            del model, tokenizer
            if gpu_available:
                torch.cuda.empty_cache()
            
    except ImportError as e:
        print(f"[ERROR] Required packages not installed: {e}")
        print("[FIX] Run: pip install transformers torch")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        print("[NOTE] Models will be downloaded automatically on first use")
        return False
    
    print(f"\\n[SUCCESS] All Qwen2.5-Coder models downloaded successfully!")
    print(f"[READY] Security analysis is ready to run offline")
    return True

if __name__ == "__main__":
    download_models()
