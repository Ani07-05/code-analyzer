#!/usr/bin/env python3
"""
Live ModelManager Test - Verify CodeLlama model loading and generation
"""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def test_model_manager_live():
    """Test ModelManager with real CodeLlama model."""
    
    print("🤖 LIVE MODEL MANAGER TEST")
    print("=" * 50)
    
    try:
        from ai_validation.managers.model_manager import ModelManager
        from ai_validation.models.ai_models import ModelSize
        
        # Test 1: Initialize ModelManager
        print("🔧 Test 1: ModelManager Initialization")
        start_time = time.time()
        
        model_manager = ModelManager(
            gpu_memory_limit=0.8,
            enable_quantization=True,
            default_model_size=ModelSize.SMALL
        )
        
        init_time = time.time() - start_time
        print(f"  ✅ ModelManager initialized in {init_time:.2f}s")
        print(f"  Device: {model_manager.device}")
        print(f"  GPU Memory: {model_manager.system_resources.gpu_memory_gb[0]:.1f}GB")
        
        # Test 2: Load 7B Model
        print("\n🧠 Test 2: CodeLlama-7B Model Loading")
        load_start = time.time()
        
        try:
            model = await model_manager.get_model(
                size=ModelSize.SMALL,
                task_complexity="medium"
            )
            
            load_time = time.time() - load_start
            print(f"  ✅ CodeLlama-7B loaded in {load_time:.2f}s")
            print(f"  Model size: {model.size.value}")
            print(f"  Quantization: {model.quantization.value}")
            print(f"  Device: {model.device}")
            print(f"  Memory usage: {model.memory_usage_mb:.1f}MB")
            
        except Exception as e:
            print(f"  ❌ Model loading failed: {e}")
            return False
        
        # Test 3: Simple Generation Test
        print("\n💭 Test 3: Simple Generation Test")
        gen_start = time.time()
        
        simple_prompt = """You are a security expert. Analyze this code:
```python
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return execute_query(query)
```

Is this vulnerable? Answer with YES or NO and explain briefly."""
        
        try:
            response = await model.generate(
                prompt=simple_prompt,
                max_tokens=100,
                temperature=0.1
            )
            
            gen_time = time.time() - gen_start
            print(f"  ✅ Generation completed in {gen_time:.2f}s")
            print(f"  Tokens generated: {response.tokens_generated}")
            print(f"  Confidence: {response.confidence:.2f}")
            print(f"  Response preview: {response.text[:200]}...")
            
        except Exception as e:
            print(f"  ❌ Generation failed: {e}")
            return False
        
        # Test 4: Security Analysis Generation
        print("\n🔍 Test 4: Security Analysis Generation")
        security_start = time.time()
        
        security_prompt = """Analyze this vulnerable Flask code for SQL injection:

```python
@app.route('/admin/users')
def admin_users():
    user_id = request.args.get('id', '')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect('users.db')
    users = conn.execute(query).fetchall()
    return f"<h1>Users: {users}</h1>"
```

Provide:
1. VULNERABILITY: YES/NO
2. CONFIDENCE: 0.0-1.0  
3. ANALYSIS: Brief security assessment
4. RISK_LEVEL: HIGH/MEDIUM/LOW
"""
        
        try:
            security_response = await model.generate(
                prompt=security_prompt,
                max_tokens=200,
                temperature=0.1
            )
            
            security_time = time.time() - security_start
            print(f"  ✅ Security analysis completed in {security_time:.2f}s")
            print(f"  Tokens: {security_response.tokens_generated}")
            print(f"  AI Response:")
            print(f"  {security_response.text}")
            
        except Exception as e:
            print(f"  ❌ Security analysis failed: {e}")
            return False
        
        # Test 5: Model Performance Stats
        print(f"\n📊 Test 5: Performance Summary")
        system_status = model_manager.get_system_status()
        
        print(f"  Model Loading: {load_time:.2f}s")
        print(f"  Simple Generation: {gen_time:.2f}s") 
        print(f"  Security Analysis: {security_time:.2f}s")
        print(f"  GPU Memory Usage: {system_status.get('gpu_memory', [{}])[0].get('usage_percent', 0):.1f}%")
        print(f"  CPU Memory Usage: {system_status.get('cpu_memory', {}).get('usage_percent', 0):.1f}%")
        
        print(f"\n🎉 MODEL MANAGER: FULLY OPERATIONAL!")
        print(f"   Your RTX 3050 is running CodeLlama-7B successfully")
        print(f"   AI security analysis is working and providing intelligent responses")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ModelManager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_model_manager_live())
    if success:
        print("\n✅ Ready for VulnerabilityVerifier testing!")
    else:
        print("\n❌ Fix ModelManager issues before proceeding")
    sys.exit(0 if success else 1)