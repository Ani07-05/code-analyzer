# Test Suite - Code Security Analyzer

Comprehensive test suite for the 4-phase security analysis pipeline.

## Directory Structure

```
tests/
├── phase1/           # Entry Point Detection Tests
├── phase2/           # RAG & Stack Overflow Tests  
├── phase3/           # AI Validation Tests
├── phase4/           # Report Generation Tests
├── integration/      # Full Pipeline Integration Tests
├── demos/           # Demo Scripts and Examples
├── unit/            # Unit Tests for Individual Components
├── performance/     # Performance and Benchmark Tests
└── fixtures/        # Test Data and Fixtures
```

## Test Categories

### Phase 1 Tests (Entry Point Detection)
- `test_day1_setup.py` - Basic setup and entry point detection

### Phase 2 Tests (RAG & Citations)
- `test_stack_overflow_citations.py` - Stack Overflow API integration

### Phase 3 Tests (AI Validation)
- `test_ai_*.py` - AI component testing
- `test_model_*.py` - Model management and loading
- `test_rtx*.py` - RTX 3050 optimization tests
- `test_vulnerability_*.py` - Vulnerability verification
- `test_consensus_*.py` - Multi-model consensus
- `test_fix_*.py` - Fix quality validation

### Phase 4 Tests (Report Generation)
- Test HTML report generation
- Test enhanced styling and interactivity
- Test different output formats

### Integration Tests
- `test_vulnerable_*.py` - End-to-end pipeline tests
- `test_real_vulns.py` - Real vulnerability detection
- `test_day2_production.py` - Production readiness
- `test_migration.py` - Migration and compatibility

### Demo Scripts
- `demo_*.py` - Various demonstration scripts
- Complete pipeline showcases
- Feature demonstrations

## Running Tests

### Individual Phase Tests
```bash
# Phase 1 - Entry Point Detection
python tests/phase1/test_day1_setup.py

# Phase 2 - RAG & Citations  
python tests/phase2/test_stack_overflow_citations.py

# Phase 3 - AI Validation
python tests/phase3/test_ai_components_direct.py

# Phase 4 - Report Generation
python tests/phase4/test_enhanced_reports.py
```

### Integration Tests
```bash
# Complete pipeline test
python tests/integration/test_vulnerable_code.py

# Production readiness
python tests/integration/test_day2_production.py
```

### Demo Scripts
```bash
# Complete system demo
python tests/demos/demo_final_phase4.py

# Individual feature demos
python tests/demos/demo_complete_system.py
```

## Test Requirements

- **Hardware**: RTX 3050 (4GB VRAM) or compatible GPU
- **Model**: CodeLlama-7b downloaded and configured
- **Dependencies**: All requirements from requirements*.txt files
- **Network**: Internet access for Stack Overflow API tests

## Expected Results

### Phase 1 Tests
- [OK] Entry point detection working
- [OK] Risk assessment functional
- [OK] Framework detection operational

### Phase 2 Tests
- [OK] Stack Overflow API integration
- [OK] Citation retrieval and ranking
- [OK] Evidence-based recommendations

### Phase 3 Tests
- [OK] AI model loading and inference
- [OK] VRAM optimization for RTX 3050
- [OK] Multi-model consensus working
- [OK] Fix quality validation functional

### Phase 4 Tests
- [OK] HTML report generation
- [OK] Enhanced dark theme styling
- [OK] Interactive JavaScript features
- [OK] Professional presentation

### Integration Tests
- [OK] Complete 4-phase pipeline working
- [OK] End-to-end vulnerability analysis
- [OK] Professional HTML reports generated
- [OK] Production-ready performance

## Performance Benchmarks

- **Phase 1**: < 5 seconds for entry point detection
- **Phase 2**: < 15 seconds for RAG analysis with citations
- **Phase 3**: < 60 seconds for AI validation (RTX 3050)
- **Phase 4**: < 10 seconds for HTML report generation
- **Complete Pipeline**: < 2 minutes total

## Troubleshooting

### Common Issues

1. **CUDA/GPU Issues**
   ```bash
   python tests/phase3/test_rtx3050.py
   ```

2. **Model Loading Problems**
   ```bash
   python tests/phase3/test_model_manager.py
   ```

3. **Stack Overflow API Rate Limiting**
   ```bash
   python tests/phase2/test_stack_overflow_citations.py
   ```

4. **Memory Issues**
   - Ensure 4GB+ VRAM available
   - Close unnecessary applications
   - Use hybrid CPU+GPU processing

### Support

For issues or questions:
1. Check test output logs
2. Verify hardware requirements
3. Ensure all dependencies installed
4. Test individual components first