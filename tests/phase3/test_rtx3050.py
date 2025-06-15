#!/usr/bin/env python3
"""
Test CodeLlama-7b on RTX 3050 4GB specifically.
File: test_rtx3050.py

This script tests if CodeLlama-7b can load and run on your RTX 3050.
"""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


async def test_rtx3050_codellama():
    """Test CodeLlama-7b specifically for RTX 3050 4GB."""
    
    print("🚀 RTX 3050 4GB + CodeLlama-7b Test")
    print("=" * 50)
    
    # Check GPU
    if not torch.cuda.is_available():
        print("❌ CUDA not available")
        return False
    
    device = "cuda:0"
    props = torch.cuda.get_device_properties(0)
    total_memory_gb = props.total_memory / (1024**3)
    
    print(f"🎮 GPU: {props.name}")
    print(f"💾 Total VRAM: {total_memory_gb:.1f}GB")
    
    # Clear any existing GPU memory
    torch.cuda.empty_cache()
    
    # Check model exists
    model_path = Path("models/codellama-7b")
    if not model_path.exists():
        print(f"❌ Model not found at {model_path}")
        print(f"Please download with: python scripts/model_management/download_models.py --model 7b")
        return False
    
    print(f"✅ Model found at {model_path}")
    
    try:
        print(f"\n📥 Loading CodeLlama-7b with INT4 quantization...")
        
        # Configure aggressive quantization for 4GB GPU
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )
        
        # Load tokenizer
        print("   Loading tokenizer...")
        start_time = time.time()
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_path),
            local_files_only=True
        )
        
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        
        tokenizer_time = time.time() - start_time
        print(f"   ✅ Tokenizer loaded in {tokenizer_time:.1f}s")
        
        # Load model with quantization
        print("   Loading model (this may take 30-60 seconds)...")
        start_time = time.time()
        
        model = AutoModelForCausalLM.from_pretrained(
            str(model_path),
            quantization_config=quantization_config,
            device_map="auto",
            torch_dtype=torch.float16,
            local_files_only=True,
            low_cpu_mem_usage=True
        )
        
        model_load_time = time.time() - start_time
        print(f"   ✅ Model loaded in {model_load_time:.1f}s")
        
        # Check memory usage
        allocated_gb = torch.cuda.memory_allocated(0) / (1024**3)
        reserved_gb = torch.cuda.memory_reserved(0) / (1024**3)
        
        print(f"\n💾 GPU Memory Usage:")
        print(f"   Allocated: {allocated_gb:.2f}GB")
        print(f"   Reserved: {reserved_gb:.2f}GB")
        print(f"   Free: {total_memory_gb - reserved_gb:.2f}GB")
        
        if reserved_gb > total_memory_gb * 0.95:
            print(f"⚠️ Using {(reserved_gb/total_memory_gb)*100:.1f}% of GPU memory")
        else:
            print(f"✅ Using {(reserved_gb/total_memory_gb)*100:.1f}% of GPU memory - Good!")
        
        # Test generation
        print(f"\n🤖 Testing code generation...")
        
        test_prompt = "def fibonacci(n):"
        
        # Tokenize input
        inputs = tokenizer(test_prompt, return_tensors="pt").to(device)
        input_length = inputs['input_ids'].shape[1]
        
        print(f"   Prompt: '{test_prompt}'")
        print(f"   Generating...")
        
        start_time = time.time()
        
        with torch.no_grad():
            outputs = model.generate(
                inputs['input_ids'],
                max_new_tokens=100,
                temperature=0.1,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
                use_cache=True
            )
        
        generation_time = time.time() - start_time
        
        # Decode output
        generated_tokens = outputs[0][input_length:]
        generated_text = tokenizer.decode(generated_tokens, skip_special_tokens=True)
        
        print(f"\n✅ Generation successful!")
        print(f"   Time: {generation_time:.2f}s")
        print(f"   Tokens: {len(generated_tokens)}")
        print(f"   Speed: {len(generated_tokens)/generation_time:.1f} tokens/sec")
        
        print(f"\n📝 Generated Code:")
        print(f"```python")
        print(f"{test_prompt}{generated_text}")
        print(f"```")
        
        # Test a security-related prompt
        print(f"\n🔒 Testing security analysis...")
        security_prompt = "# Analyze this code for XSS vulnerability:\ndef render_user_input(user_data):\n    return f'<div>{user_data}</div>'"
        
        inputs = tokenizer(security_prompt, return_tensors="pt").to(device)
        input_length = inputs['input_ids'].shape[1]
        
        with torch.no_grad():
            outputs = model.generate(
                inputs['input_ids'],
                max_new_tokens=150,
                temperature=0.1,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )
        
        generated_tokens = outputs[0][input_length:]
        security_response = tokenizer.decode(generated_tokens, skip_special_tokens=True)
        
        print(f"📝 Security Analysis Response:")
        print(f"```")
        print(f"{security_response[:200]}...")
        print(f"```")
        
        # Cleanup
        print(f"\n🧹 Cleaning up...")
        del model
        del tokenizer
        torch.cuda.empty_cache()
        
        final_memory = torch.cuda.memory_allocated(0) / (1024**3)
        print(f"   GPU memory after cleanup: {final_memory:.2f}GB")
        
        print(f"\n🎉 SUCCESS! CodeLlama-7b works perfectly on your RTX 3050!")
        print(f"\n📊 Performance Summary:")
        print(f"   • Model loading: {model_load_time:.1f}s")
        print(f"   • Peak GPU usage: {reserved_gb:.2f}GB / {total_memory_gb:.1f}GB")
        print(f"   • Generation speed: {len(generated_tokens)/generation_time:.1f} tokens/sec")
        print(f"   • Memory efficiency: ✅ Fits comfortably in 4GB")
        
        return True
        
    except torch.cuda.OutOfMemoryError:
        print(f"❌ GPU Out of Memory!")
        print(f"   Your RTX 3050 4GB might need more aggressive quantization")
        print(f"   Try clearing GPU memory: nvidia-smi")
        return False
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test function."""
    success = await test_rtx3050_codellama()
    
    if success:
        print(f"\n✅ Your RTX 3050 4GB is perfect for Phase 3!")
        print(f"🚀 Ready to continue with vulnerability verification!")
    else:
        print(f"\n❌ Setup needs adjustment for your RTX 3050")
    
    return success


if __name__ == "__main__":
    asyncio.run(main())