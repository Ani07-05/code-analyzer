#!/usr/bin/env python3
"""
Code Security Analyzer - Setup Script
Prepares the environment for security analysis

Usage:
    python setup.py              # Basic setup
    python setup.py --with-ai    # Setup with AI models
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

def print_banner():
    """Print setup banner"""
    print("=" * 60)
    print("       CODE SECURITY ANALYZER SETUP")
    print("=" * 60)
    print()

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print("Error: Python 3.9 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"Python version: {sys.version.split()[0]} ✓")
    return True

def install_dependencies():
    """Install required dependencies"""
    print("Installing dependencies...")
    
    try:
        # Install basic requirements
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("Dependencies installed successfully ✓")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def setup_ai_models():
    """Setup AI models for analysis"""
    print("Setting up AI models...")
    
    models_dir = Path("models")
    codellama_dir = models_dir / "codellama-7b"
    
    if codellama_dir.exists():
        print("CodeLlama 7B model found ✓")
        return True
    else:
        print("CodeLlama 7B model not found")
        print("Please download the model manually or run:")
        print("  python scripts/model_management/download_models.py")
        return False

def check_system_requirements():
    """Check system requirements"""
    print("Checking system requirements...")
    
    # Check CUDA availability
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            print(f"GPU: {gpu_name} ({vram_gb:.1f}GB VRAM) ✓")
        else:
            print("GPU: Not available (CPU-only mode)")
    except ImportError:
        print("PyTorch not installed yet")
    
    return True

def create_directories():
    """Create necessary directories"""
    dirs = ["reports", "cache", "logs"]
    
    for dir_name in dirs:
        dir_path = Path(dir_name)
        dir_path.mkdir(exist_ok=True)
        print(f"Directory: {dir_name} ✓")

def main():
    """Main setup function"""
    print_banner()
    
    parser = argparse.ArgumentParser(description="Setup Code Security Analyzer")
    parser.add_argument("--with-ai", action="store_true", help="Setup AI models")
    parser.add_argument("--quick", action="store_true", help="Quick setup without AI")
    args = parser.parse_args()
    
    success = True
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        success = False
    
    # Check system requirements
    check_system_requirements()
    
    # Setup AI models if requested
    if args.with_ai and not args.quick:
        if not setup_ai_models():
            print("Warning: AI models not fully configured")
    
    print()
    if success:
        print("=" * 60)
        print("SETUP COMPLETE")
        print("=" * 60)
        print()
        print("You can now run security analysis:")
        print("  python analyze.py .                    # Basic analysis")
        print("  python analyze.py . --enable-ai       # With AI validation")
        print("  python analyze.py . --quick           # Quick scan")
        print()
        print("For help:")
        print("  python analyze.py --help")
        print()
    else:
        print("Setup completed with warnings. Check messages above.")

if __name__ == "__main__":
    main()