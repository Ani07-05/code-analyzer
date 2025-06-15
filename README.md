# Code Security Analyzer

Advanced vulnerability detection with AI-powered analysis using local CodeLlama models.

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd code-security-analyzer
python setup.py --with-ai  # Setup with AI models
```

### 2. Run Analysis
```bash
# Basic analysis (fast)
python analyze.py /path/to/your/project

# With AI validation (recommended)
python analyze.py /path/to/your/project --enable-ai

# Quick scan without AI
python analyze.py /path/to/your/project --quick
```

### 3. View Results
Open the generated HTML report in your browser for interactive vulnerability analysis.

## 📋 Features

### 4-Phase Analysis Pipeline
1. **Entry Point Detection** - Identify application entry points and risk assessment
2. **RAG-powered Fix Generation** - Evidence-based fixes with Stack Overflow citations
3. **AI Validation** - CodeLlama 7B model for intelligent vulnerability verification
4. **Professional Reporting** - Interactive HTML reports with detailed analysis

### Supported Technologies
- **Python**: Flask, Django, FastAPI
- **JavaScript**: Node.js, Express (coming soon)
- **Security Patterns**: SQL Injection, XSS, Authentication, Input Validation

### AI Models
- **CodeLlama 7B**: Local analysis with GPU acceleration
- **Hybrid Processing**: CPU+GPU optimization for 4GB+ VRAM
- **Privacy-First**: All analysis runs locally

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- 4GB+ RAM (8GB+ recommended for AI features)
- Optional: NVIDIA GPU with 4GB+ VRAM for faster AI processing

### Basic Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Create necessary directories
python setup.py
```

### AI Model Setup
```bash
# Download CodeLlama 7B model (optional)
python scripts/model_management/download_models.py

# Or setup manually
python setup.py --with-ai
```

## 📖 Usage Examples

### Command Line Options
```bash
# Analyze current directory
python analyze.py .

# Analyze specific project with AI
python analyze.py /path/to/project --enable-ai

# Custom output file
python analyze.py . --output my_security_report.html

# JSON output for CI/CD integration
python analyze.py . --format json --output results.json

# Quick scan (no AI, faster)
python analyze.py . --quick

# Run specific phases
python analyze.py . --phases 1  # Entry detection only
python analyze.py . --phases 3  # AI validation only
```

### Output Formats
- **HTML**: Interactive report with charts and detailed analysis
- **JSON**: Machine-readable format for automation
- **Text**: Simple text summary

## 🔧 Configuration

### GPU Requirements
- **8GB+ VRAM**: Full AI processing with 13B models
- **4GB+ VRAM**: Hybrid CPU+GPU processing with 7B models  
- **<4GB VRAM**: CPU-only processing (slower but functional)

### Performance Optimization
- Enable GPU acceleration for faster analysis
- Use `--quick` mode for rapid scans
- Run specific phases with `--phases` for targeted analysis

## 📊 Sample Output

```
======================================================================
           CODE SECURITY ANALYZER
         Advanced Vulnerability Detection
======================================================================

Phase 1: Entry Point Detection
----------------------------------------
Files Scanned: 25
Entry Points Found: 8
High Risk: 3
Moderate Risk: 2
Low Risk: 3

Phase 3: AI Validation with CodeLlama 7B
----------------------------------------
Loading CodeLlama 7B model...
Analyzing 3 high-risk entry points with AI...
AI validation completed

======================================================================
ANALYSIS COMPLETE
======================================================================
Files Analyzed: 25
Entry Points Found: 8
High Risk Issues: 3
Report Generated: security_report_20231215_143022.html
```

## 🔍 What Gets Analyzed

### Vulnerability Types
- **SQL Injection**: Direct query construction, ORM misuse
- **Cross-Site Scripting (XSS)**: Template injection, unsafe output
- **Authentication Issues**: Weak session handling, missing auth
- **Input Validation**: Unvalidated user inputs, path traversal
- **Authorization**: Missing access controls, privilege escalation
- **Cryptographic Issues**: Weak encryption, hardcoded secrets

### Code Patterns
- Entry point identification (routes, endpoints, handlers)
- Data flow analysis from user input to sensitive operations
- Security feature detection (validation, sanitization, auth)
- Framework-specific vulnerability patterns

## 🚀 Integration

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Security Analysis
  run: |
    python analyze.py . --format json --output security-results.json
    # Upload results or fail build based on findings
```

### IDE Integration
- VS Code extension (coming soon)
- IntelliJ plugin (planned)

## 🛡️ Privacy & Security

### Local Processing
- All analysis runs on your machine
- No code sent to external services
- AI models run locally with your data

### Data Handling
- No persistent storage of analyzed code
- Temporary analysis cache (can be cleared)
- Optional result export only

## 🐛 Troubleshooting

### Common Issues

**GPU Memory Errors**
```bash
# Reduce memory usage
export CUDA_VISIBLE_DEVICES=""  # Force CPU mode
python analyze.py . --quick      # Skip AI analysis
```

**Missing Dependencies**
```bash
pip install -r requirements.txt
python setup.py  # Re-run setup
```

**Model Loading Issues**
```bash
# Check model availability
ls models/codellama-7b/
# Download if missing
python scripts/model_management/download_models.py
```

### Performance Tips
- Use SSD storage for model files
- Close other GPU applications during analysis
- Use `--quick` mode for rapid iteration
- Enable verbose mode `--verbose` for debugging

## 📈 Roadmap

### Upcoming Features
- **Multi-language Support**: Java, C#, Go, Rust
- **Advanced AI Models**: GPT integration, custom models
- **Team Dashboard**: Central vulnerability tracking
- **Compliance Reporting**: SOC2, PCI-DSS, HIPAA mapping
- **Auto-remediation**: Automatic security fix generation

### Performance Improvements
- **Model Quantization**: Faster inference with lower memory
- **Incremental Analysis**: Only scan changed files
- **Parallel Processing**: Multi-core vulnerability detection
- **Result Caching**: Avoid re-analysis of unchanged code

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md] for guidelines.

## 📄 License

MIT License - see [LICENSE] file for details.

## 🆘 Support

- **Issues**: GitHub Issues for bug reports
- **Documentation**: See `/docs` directory
- **Performance**: Check system requirements above

---

**Made with ❤️ for secure coding practices**