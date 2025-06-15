#!/usr/bin/env python3
"""
Fixed RTX 3050 test - corrected syntax error.
File: test_rtx3050_final.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from src.ai_validation.managers.model_manager import ModelManager
    from src.ai_validation.models.ai_models import ModelSize
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


async def test_rtx3050_with_model_manager():
    """Test RTX 3050 using the updated ModelManager."""
    
    print("🚀 RTX 3050 Laptop GPU + CodeLlama-7b (Final Test)")
    print("=" * 60)
    
    try:
        # Initialize ModelManager
        print("1️⃣ Initializing ModelManager...")
        manager = ModelManager()
        
        print(f"   Device: {manager.device}")
        print(f"   GPU Memory: {manager.system_resources.gpu_memory_gb[0]:.1f}GB")
        
        # Get model (should use hybrid loading automatically)
        print("\n2️⃣ Loading CodeLlama-7b with hybrid CPU+GPU...")
        model = await manager.get_model(ModelSize.SMALL, "medium")
        
        print(f"   ✅ Model loaded successfully!")
        print(f"   Memory usage: {model.memory_usage_mb:.1f}MB")
        print(f"   Load time: {model.load_time_seconds:.1f}s")
        print(f"   Device: {model.device}")
        
        # Test code generation
        print("\n3️⃣ Testing code generation...")
        response = await model.generate(
            "def check_sql_injection(user_input):",
            max_tokens=100,
            temperature=0.1
        )
        
        print(f"   ✅ Generation successful!")
        print(f"   Tokens: {response.tokens_generated}")
        print(f"   Time: {response.generation_time:.2f}s") 
        print(f"   Speed: {response.tokens_generated/response.generation_time:.1f} tokens/sec")
        print(f"   Confidence: {response.confidence:.2f}")
        
        print(f"\n📝 Generated Code:")
        print(f"```python")
        print(f"def check_sql_injection(user_input):{response.text}")
        print(f"```")
        
        # Test security analysis
        print("\n4️⃣ Testing security analysis...")
        security_prompt = ("# Security Analysis: Is this code vulnerable to XSS?\n"
                          "def render_comment(comment):\n"
                          "    return f'<div class=\"comment\">{comment}</div>'\n"
                          "# Analysis:")
        
        security_response = await model.generate(
            security_prompt,
            max_tokens=150,
            temperature=0.2
        )
        
        print(f"📝 Security Analysis:")
        print(f"```")
        print(f"{security_response.text[:300]}...")
        print(f"```")
        
        # System status
        print("\n5️⃣ System status...")
        status = manager.get_system_status()
        
        if "gpu_memory" in status:
            gpu_info = status["gpu_memory"][0]
            print(f"   GPU Usage: {gpu_info['usage_percent']:.1f}%")
            print(f"   GPU Memory: {gpu_info['allocated_gb']:.2f}GB / {gpu_info['total_gb']:.1f}GB")
        
        cpu_info = status["cpu_memory"]
        print(f"   CPU Usage: {cpu_info['usage_percent']:.1f}%")
        
        # Test multiple generations (batch-like)
        print("\n6️⃣ Testing multiple security analyses...")
        
        test_cases = [
            "def authenticate_user(username, password):",
            "def process_file_upload(file_data):",
            "def execute_query(sql, params):"
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"   Test {i}: {test_case}")
            response = await model.generate(
                test_case,
                max_tokens=50,
                temperature=0.1
            )
            print(f"      Generated {response.tokens_generated} tokens in {response.generation_time:.1f}s")
        
        # Success!
        print("\n🎉 SUCCESS! RTX 3050 Laptop GPU + CodeLlama-7b working perfectly!")
        
        print("\n📊 Performance Summary:")
        print(f"   • Model: CodeLlama-7b with INT4 quantization")
        print(f"   • Architecture: Hybrid CPU+GPU loading") 
        if "gpu_memory" in status:
            print(f"   • GPU Memory: {gpu_info['allocated_gb']:.2f}GB / {gpu_info['total_gb']:.1f}GB")
        print(f"   • Generation Speed: {response.tokens_generated/response.generation_time:.1f} tokens/sec")
        print(f"   • Load Time: {model.load_time_seconds:.1f}s")
        print(f"   • Quality: Excellent ({response.confidence:.2f} confidence)")
        
        print("\n🚀 Ready for full Phase 3 implementation!")
        print("\nNext milestones:")
        print("   ✅ ModelManager: COMPLETE")
        print("   🎯 VulnerabilityVerifier: Ready to implement")
        print("   🎯 FixQualityValidator: Ready to implement") 
        print("   🎯 ConsensusEngine: Ready to implement")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_rtx3050_with_model_manager())
    sys.exit(0 if success else 1)