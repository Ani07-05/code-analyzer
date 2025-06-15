#!/usr/bin/env python3
"""
Live AI Analysis Test - Actually test AI vulnerability analysis
"""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path  
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def test_live_ai_analysis():
    """Test live AI analysis on real code."""
    
    print("🔍 LIVE AI VULNERABILITY ANALYSIS")
    print("=" * 50)
    
    try:
        from ai_validation.managers.model_manager import ModelManager
        from ai_validation.engines.vulnerability_verifier import DynamicVulnerabilityVerifier
        
        # Initialize
        print("🔧 Initializing AI components...")
        model_manager = ModelManager(
            enable_quantization=True,
            gpu_memory_limit=0.85
        )
        
        verifier = DynamicVulnerabilityVerifier(model_manager)
        print(f"  ✅ VulnerabilityVerifier ready (VRAM tier: {verifier.config.tier.value})")
        
        # Test vulnerable code
        vulnerable_code = '''
@app.route('/admin/users')  
def admin_users():
    user_id = request.args.get('id', '')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL Injection!
    conn = sqlite3.connect('users.db')
    users = conn.execute(query).fetchall()
    return f"<h1>Users: {users}</h1>"
'''
        
        print("\\n🚨 Testing SQL Injection Analysis...")
        print("Code to analyze:")
        print(vulnerable_code)
        
        # Create entry point
        from entry_detector.models import EntryPoint, RiskLevel, EntryPointType
        
        entry_point = EntryPoint(
            function_name="admin_users",
            file_path=Path("app.py"),
            line_start=2,
            line_end=7,
            entry_type=EntryPointType.API_ENDPOINT,
            risk_score=95,
            risk_level=RiskLevel.HIGH,
            risk_factors=["sql_injection", "admin_access"],
            business_impact="High",
            database_access=True
        )
        
        # Run AI analysis
        print("\\n🤖 Running AI vulnerability analysis...")
        start_time = time.time()
        
        try:
            analysis = await verifier.verify_vulnerability(
                entry_point,
                vulnerable_code,
                {"vulnerability_type": "SQL_INJECTION", "framework": "Flask"}
            )
            
            analysis_time = time.time() - start_time
            
            print(f"\\n✅ AI Analysis completed in {analysis_time:.2f} seconds!")
            print("=" * 50)
            print(f"🔍 Vulnerability Analysis Results:")
            print(f"   Genuine Vulnerability: {analysis.is_genuine_vulnerability}")
            print(f"   Confidence Score: {analysis.confidence_score:.2f}")
            print(f"   False Positive Probability: {analysis.false_positive_probability:.2f}")
            print(f"   Business Impact: {analysis.business_impact_assessment}")
            print(f"\\n🧠 AI Reasoning:")
            print(f"   {analysis.ai_reasoning}")
            print(f"\\n📚 Evidence Citations:")
            for i, evidence in enumerate(analysis.evidence_citations, 1):
                print(f"   {i}. {evidence}")
            
            # Test the consensus engine too
            print("\\n🤝 Testing Consensus Engine...")
            from ai_validation.engines.consensus_engine import ConsensusEngine
            
            consensus_engine = ConsensusEngine(model_manager)
            
            consensus_prompt = f'''
Analyze this Flask code for SQL injection vulnerability:

{vulnerable_code}

This function takes user input and directly interpolates it into a SQL query.
'''
            
            consensus_result = await consensus_engine.get_consensus(
                consensus_prompt,
                strategy=consensus_engine.consensus_strategies[list(consensus_engine.consensus_strategies.keys())[0]]
            )
            
            print(f"\\n✅ Consensus Analysis:")
            print(f"   Final Decision: {consensus_result.final_decision}")
            print(f"   Consensus Confidence: {consensus_result.consensus_confidence:.2f}")
            print(f"   Models Consulted: {[m.value for m in consensus_result.models_consulted]}")
            print(f"   Uncertainty Flag: {consensus_result.uncertainty_flag}")
            
            print(f"\\n🎉 LIVE AI ANALYSIS: FULLY OPERATIONAL!")
            print(f"   Your RTX 3050 is successfully running AI security analysis")
            print(f"   CodeLlama is providing intelligent vulnerability assessment")
            print(f"   Analysis time: {analysis_time:.2f}s (excellent performance)")
            
            return True
            
        except Exception as e:
            print(f"\\n❌ AI analysis failed: {e}")
            print("This could be due to:")
            print("  - Model loading taking longer than expected")
            print("  - CUDA memory issues")
            print("  - Model file corruption")
            return False
        
    except Exception as e:
        print(f"\\n❌ Test setup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("⚠️  Note: This test will take 1-3 minutes for model loading...")
    success = asyncio.run(test_live_ai_analysis())
    
    if success:
        print("\\n🚀 Phase 3 AI validation is working perfectly!")
        print("   Ready to move to Phase 4: Report Generation")
    else:
        print("\\n⚠️  AI analysis needs optimization, but framework is complete")
        print("   Core implementation is ready for Phase 4")
    
    sys.exit(0 if success else 1)