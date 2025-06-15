#!/usr/bin/env python3
"""Download and setup CodeLlama models for Phase 3."""

import os
import sys
from pathlib import Path

def download_models():
    """Download CodeLlama models."""
    print("[DOWNLOAD] CodeLlama models...")
    
    models = [
        ("codellama/CodeLlama-7b-Instruct-hf", "models/codellama-7b"),
        ("codellama/CodeLlama-13b-Instruct-hf", "models/codellama-13b"),
    ]
    
    try:
        from huggingface_hub import snapshot_download
        
        for model_id, local_path in models:
            print(f"[DOWNLOADING] {model_id}...")
            snapshot_download(
                repo_id=model_id,
                local_dir=local_path,
                local_dir_use_symlinks=False,
                resume_download=True
            )
            print(f"[SUCCESS] Downloaded to {local_path}")
            
    except ImportError:
        print("[ERROR] huggingface_hub not installed. Run: pip install huggingface_hub")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        sys.exit(1)
    
    print("[SUCCESS] All models downloaded successfully!")

if __name__ == "__main__":
    download_models()
