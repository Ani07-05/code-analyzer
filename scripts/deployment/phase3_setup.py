#!/usr/bin/env python3
"""Phase 3 setup and validation script."""

import subprocess
import sys
from pathlib import Path

def setup_phase3():
    """Setup Phase 3 environment."""
    print("[SETUP] Phase 3 AI Validation Layer...")
    
    # Install dependencies
    print("[INSTALL] Dependencies...")
    result = subprocess.run([
        sys.executable, "-m", "pip", "install", 
        "-r", "requirements_phase3.txt"
    ])
    
    if result.returncode != 0:
        print("[ERROR] Failed to install dependencies")
        return False
    
    # Validate installation
    print("[VALIDATE] Installation...")
    try:
        import torch
        import transformers
        print(f"[OK] PyTorch: {torch.__version__}")
        print(f"[OK] Transformers: {transformers.__version__}")
        
        if torch.cuda.is_available():
            print(f"[OK] CUDA available: {torch.cuda.device_count()} GPUs")
        else:
            print("[WARNING] CUDA not available - will use CPU")
            
    except ImportError as e:
        print(f"[ERROR] Import error: {e}")
        return False
    
    print("[SUCCESS] Phase 3 setup completed successfully!")
    print("Next: Download models with scripts/model_management/download_models.py")
    return True

if __name__ == "__main__":
    success = setup_phase3()
    sys.exit(0 if success else 1)
