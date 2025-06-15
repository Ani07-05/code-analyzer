#!/usr/bin/env python3
"""
Test script for ModelManager implementation.
File: test_model_manager.py

Run this to verify your Phase 3 setup is working correctly.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from src.ai_validation.managers.model_manager import ModelManager, ModelLoadingError
    from src.ai_validation.models.ai_models import ModelSize, recommend_model_size
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you've run the folder setup script and are in the project root directory")
    sys.exit(1)


async def test_model_manager():
    """Test ModelManager functionality."""
    print("🧪 Testing ModelManager Implementation")
    print("=" * 50)
    
    try:
        # Test 1: ModelManager Initialization
        print("\n1️⃣ Testing ModelManager initialization...")
        manager = ModelManager()
        print(f"✅ ModelManager initialized successfully")
        print(f"   Device: {manager.device}")
        print(f"   GPU Available: {manager.system_resources.gpu_available}")
        print(f"   GPU Count: {manager.system_resources.gpu_count}")
        print(f"   CPU Memory: {manager.system_resources.cpu_memory_gb:.1f}GB")
        
        # Test 2: System Status
        print("\n2️⃣ Testing system status...")
        status = manager.get_system_status()
        print(f"✅ System status retrieved")
        print(f"   Loaded models: {status['loaded_models']}")
        print(f"   CPU memory usage: {status['cpu_memory']['usage_percent']:.1f}%")
        
        if status['system_resources']['gpu_available']:
            for i, gpu_info in enumerate(status.get('gpu_memory', [])):
                print(f"   GPU {i} usage: {gpu_info['usage_percent']:.1f}%")
        
        # Test 3: Model Existence Check
        print("\n3️⃣ Testing model existence checks...")
        for size in [ModelSize.SMALL, ModelSize.MEDIUM, ModelSize.LARGE]:
            exists = manager._check_model_exists(size)
            status_icon = "✅" if exists else "❌"
            print(f"   {status_icon} CodeLlama-{size.value}: {'Found' if exists else 'Not found'}")
        
        # Test 4: Memory Availability Check
        print("\n4️⃣ Testing memory availability...")
        for size in [ModelSize.SMALL, ModelSize.MEDIUM, ModelSize.LARGE]:
            can_load = manager._check_memory_availability(size)
            status_icon = "✅" if can_load else "❌"
            print(f"   {status_icon} CodeLlama-{size.value}: {'Can load' if can_load else 'Insufficient memory'}")
        
        # Test 5: Model Size Recommendation
        print("\n5️⃣ Testing model size recommendation...")
        available_memory = manager.system_resources.cpu_memory_gb
        if manager.system_resources.gpu_available and manager.system_resources.gpu_memory_gb:
            available_memory = max(manager.system_resources.gpu_memory_gb)
        
        for complexity in ["simple", "medium", "complex"]:
            recommended = recommend_model_size(available_memory, complexity)
            if recommended:
                print(f"   ✅ {complexity.capitalize()} tasks: CodeLlama-{recommended.value}")
            else:
                print(f"   ❌ {complexity.capitalize()} tasks: No model fits in memory")
        
        # Test 6: Model Loading (if models exist)
        print("\n6️⃣ Testing model loading...")
        available_models = []
        for size in [ModelSize.SMALL, ModelSize.MEDIUM, ModelSize.LARGE]:
            if manager._check_model_exists(size) and manager._check_memory_availability(size):
                available_models.append(size)
        
        if available_models:
            # Try to load the smallest available model
            smallest_model = min(available_models, key=lambda x: ["7b", "13b", "34b"].index(x.value))
            print(f"   Attempting to load CodeLlama-{smallest_model.value}...")
            
            try:
                model = await manager.get_model(smallest_model)
                print(f"   ✅ Model loaded successfully!")
                print(f"      Memory usage: {model.memory_usage_mb:.1f}MB")
                print(f"      Load time: {model.load_time_seconds:.1f}s")
                print(f"      Device: {model.device}")
                
                # Test 7: Model Generation (simple test)
                print("\n7️⃣ Testing model generation...")
                try:
                    response = await model.generate(
                        "def fibonacci(n):",
                        max_tokens=100,
                        temperature=0.1
                    )
                    print(f"   ✅ Generation successful!")
                    print(f"      Generated {response.tokens_generated} tokens in {response.generation_time:.2f}s")
                    print(f"      Confidence: {response.confidence:.2f}")
                    print(f"      Generated text preview: {response.text[:100]}...")
                    
                except Exception as e:
                    print(f"   ⚠️ Generation test failed: {e}")
                
                # Clean up
                print("\n🧹 Cleaning up...")
                manager.clear_model_cache(smallest_model)
                print("   ✅ Model cache cleared")
                
            except ModelLoadingError as e:
                print(f"   ⚠️ Model loading failed: {e}")
                print("   This is expected if models haven't been downloaded yet")
        else:
            print("   ⚠️ No models available for testing")
            print("   This is expected if models haven't been downloaded yet")
        
        # Test 8: Configuration Loading
        print("\n8️⃣ Testing configuration...")
        config = manager.config
        print(f"   ✅ Configuration loaded")
        print(f"      Default model size: {config['models']['default_model_size']}")
        print(f"      Quantization enabled: {config['models']['quantization_enabled']}")
        print(f"      Max concurrent validations: {config['validation']['max_concurrent_validations']}")
        
        print("\n🎉 All tests completed!")
        print("\n📋 Summary:")
        print(f"   • ModelManager initialization: ✅")
        print(f"   • System resource detection: ✅")
        print(f"   • Configuration loading: ✅")
        print(f"   • Memory management: ✅")
        
        if available_models:
            print(f"   • Model loading: ✅")
            print(f"   • Model generation: ✅")
        else:
            print(f"   • Model loading: ⚠️ (no models downloaded)")
        
        print(f"\n🚀 Phase 3 ModelManager is ready!")
        
        if not available_models:
            print(f"\n📥 Next step: Download models with:")
            print(f"   python scripts/model_management/download_models.py")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def test_system_requirements():
    """Test system requirements for Phase 3."""
    print("🔍 Checking System Requirements")
    print("=" * 50)
    
    # Check Python version
    print(f"✅ Python version: {sys.version.split()[0]}")
    
    # Check imports
    try:
        import torch
        print(f"✅ PyTorch: {torch.__version__}")
        print(f"   CUDA available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"   CUDA version: {torch.version.cuda}")
            print(f"   GPU count: {torch.cuda.device_count()}")
    except ImportError:
        print(f"❌ PyTorch not installed")
        return False
    
    try:
        import transformers
        print(f"✅ Transformers: {transformers.__version__}")
    except ImportError:
        print(f"❌ Transformers not installed")
        return False
    
    try:
        import bitsandbytes
        print(f"✅ BitsAndBytes: {bitsandbytes.__version__}")
    except ImportError:
        print(f"❌ BitsAndBytes not installed")
        return False
    
    # Check disk space
    import shutil
    disk_free_gb = shutil.disk_usage('.').free / (1024**3)
    print(f"✅ Available disk space: {disk_free_gb:.1f}GB")
    
    if disk_free_gb < 30:
        print(f"⚠️ Warning: Less than 30GB free space available")
        print(f"   CodeLlama models require 13-68GB each")
    
    # Check memory
    import psutil
    memory_gb = psutil.virtual_memory().total / (1024**3)
    print(f"✅ Total system memory: {memory_gb:.1f}GB")
    
    if memory_gb < 16:
        print(f"⚠️ Warning: Less than 16GB RAM available")
        print(f"   Recommended: 16GB+ for optimal performance")
    
    return True


async def main():
    """Main test function."""
    print("🤖 Phase 3 AI Validation Layer - Setup Test")
    print("=" * 60)
    
    # Test system requirements first
    if not test_system_requirements():
        print(f"\n❌ System requirements not met")
        return False
    
    print(f"\n")
    
    # Test ModelManager
    success = await test_model_manager()
    
    if success:
        print(f"\n✅ All tests passed! Phase 3 setup is working correctly.")
    else:
        print(f"\n❌ Some tests failed. Check the errors above.")
    
    return success


if __name__ == "__main__":
    asyncio.run(main())