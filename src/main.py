#!/usr/bin/env python3
"""
Code Security Analyzer - Main CLI Interface

A comprehensive security analysis tool for codebases.
Complete 4-phase security analysis with AI validation and professional reporting.
"""

import sys
import logging
import asyncio
from pathlib import Path
import click
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from cli_navigator.navigator import CLINavigator, FileType, ScanResult
from entry_detector import EntryPointDetector, EntryPointReport, RiskLevel
from utils.logger import setup_logger


def display_scan_results(result, verbose=False):
    """Display scan results in a user-friendly format"""
    click.echo("\nSCAN COMPLETE")
    click.echo("=" * 50)
    
    click.echo(f"Target: {result.target_directory}")
    click.echo(f"Duration: {result.scan_duration:.2f} seconds")
    click.echo(f"Files found: {result.total_files}")
    click.echo(f"Analyzed: {result.analyzed_files}")
    
    click.echo("\nFILE TYPES DETECTED:")
    for file_type, files in result.files_by_type.items():
        if files:
            click.echo(f"  {file_type.value:<12} {len(files):>6} files")

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx, verbose, debug):
    """
    Code Security Analyzer - Find vulnerabilities in your codebase
    
    A modular security analysis tool that scans codebases for:
    - Deprecated packages and dependencies
    - SQL injection vulnerabilities  
    - Cross-site scripting (XSS) issues
    - Authentication problems
    - Input validation gaps
    - Hardcoded secrets and credentials
    
    Start by scanning a directory to discover its structure.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Set up logging
    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    setup_logger(log_level)
    
    ctx.obj['verbose'] = verbose
    ctx.obj['debug'] = debug


@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--max-size', default=10*1024*1024, help='Maximum file size to analyze (bytes)')
@click.option('--max-depth', type=int, help='Maximum directory depth to traverse')
@click.option('--no-progress', is_flag=True, help='Disable progress display')
@click.option('--follow-symlinks', is_flag=True, help='Follow symbolic links')
@click.option('--exclude-dir', multiple=True, help='Additional directories to exclude')
@click.option('--exclude-file', multiple=True, help='Additional file patterns to exclude')
@click.option('--output', '-o', type=click.Path(), help='Save detailed results to file')
@click.pass_context
def scan(ctx, directory, max_size, max_depth, no_progress, follow_symlinks, 
         exclude_dir, exclude_file, output):
    """
    Scan a directory for code files and potential entry points
    
    This command traverses the specified directory, identifies code files,
    and provides a detailed analysis of the project structure.
    
    Examples:
        codesec scan /path/to/project
        codesec scan . --max-depth 3 --exclude-dir cache
        codesec scan ~/myapp --output scan_results.txt
    """
    # Set up navigator with options
    navigator = CLINavigator(
        max_file_size=max_size,
        max_depth=max_depth,
        excluded_dirs=set(exclude_dir) if exclude_dir else None,
        excluded_files=set(exclude_file) if exclude_file else None,
        follow_symlinks=follow_symlinks,
        show_progress=not no_progress
    )
    
    click.echo(f"Scanning directory: {directory}")
    click.echo(f"Max file size: {max_size:,} bytes")
    if max_depth:
        click.echo(f"Max depth: {max_depth}")
    
    try:
        # Perform the scan
        result = navigator.scan_directory(directory)
        
        # Display results
        display_scan_results(result, ctx.obj['verbose'])
        
        # Save to file if requested
        if output:
            save_results_to_file(result, output)
            click.echo(f"Detailed results saved to: {output}")
    
    except Exception as e:
        click.echo(f"Error during scan: {e}", err=True)
        if ctx.obj['debug']:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='entry-points')
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--show-paths', is_flag=True, help='Show full file paths')
@click.option('--framework', type=click.Choice(['flask', 'all']), default='all', 
              help='Filter by specific framework')
@click.option('--risk-level', type=click.Choice(['high', 'moderate', 'low', 'all']), 
              default='all', help='Filter by risk level')
@click.option('--output', '-o', type=click.Path(), help='Save detailed results to file')
@click.pass_context  
def entry_points(ctx, directory, show_paths, framework, risk_level, output):
    """
    Find and analyze application entry points with risk assessment
    
    Performs comprehensive entry point analysis including:
    - Framework detection (Flask supported in Phase 1)
    - Business impact risk assessment
    - Security feature detection
    - Input source analysis
    """
    click.echo(f"Analyzing entry points in: {directory}")
    
    try:
        # Step 1: CLI Navigator scan
        navigator = CLINavigator(show_progress=not ctx.obj.get('verbose', False))
        scan_result = navigator.scan_directory(directory)
        
        # Step 2: Entry point detection and analysis
        detector = EntryPointDetector()
        with click.progressbar(length=1, label='Analyzing entry points') as bar:
            report = detector.analyze_entry_points(scan_result)
            bar.update(1)
        
        # Step 3: Display results
        display_entry_point_analysis(report, framework, risk_level, show_paths)
        
        # Step 4: Save detailed results if requested
        if output:
            save_entry_point_report(report, output)
            click.echo(f"Detailed analysis saved to: {output}")
    
    except Exception as e:
        click.echo(f"Error during entry point analysis: {e}", err=True)
        if ctx.obj['debug']:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='risk-assessment')  
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--framework', type=click.Choice(['flask', 'all']), default='all',
              help='Analyze specific framework')
@click.option('--high-risk-only', is_flag=True, help='Show only high-risk entry points')
@click.option('--show-details', is_flag=True, help='Show detailed risk analysis')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'summary']), 
              default='table', help='Output format')
@click.pass_context
def risk_assessment(ctx, directory, framework, high_risk_only, show_details, output_format):
    """
    Perform business impact risk assessment of entry points
    
    Uses business-focused risk model:
    HIGH: Business-ending damage (system compromise, mass data leaks)
    MODERATE: Individual user impact (account compromise, personal data)  
    LOW: Technical debt (deprecated packages, performance issues)
    """
    click.echo(f"Performing risk assessment for: {directory}")
    
    try:
        # Scan and analyze
        navigator = CLINavigator(show_progress=False)
        scan_result = navigator.scan_directory(directory)
        
        detector = EntryPointDetector()
        report = detector.analyze_entry_points(scan_result)
        
        # Display risk assessment
        display_risk_assessment(report, framework, high_risk_only, show_details, output_format)
        
    except Exception as e:
        click.echo(f"Error during risk assessment: {e}", err=True)
        sys.exit(1)


@cli.command(name='analyze-frameworks')
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--detect-only', is_flag=True, help='Only detect frameworks, no analysis')
@click.pass_context
def analyze_frameworks(ctx, directory, detect_only):
    """
    Detect and analyze web frameworks in the codebase
    
    Currently supports:
    - Flask (Python web framework)
    
    Future support planned for:
    - Next.js, Vue.js, Express.js, Svelte, Node.js
    """
    click.echo(f"Detecting frameworks in: {directory}")
    
    try:
        navigator = CLINavigator(show_progress=False)
        scan_result = navigator.scan_directory(directory)
        
        detector = EntryPointDetector()
        
        if detect_only:
            # Quick framework detection only
            frameworks = detect_frameworks_only(scan_result, detector)
            display_framework_detection(frameworks)
        else:
            # Full analysis
            report = detector.analyze_entry_points(scan_result)
            display_framework_analysis(report)
            
    except Exception as e:
        click.echo(f"Error during framework analysis: {e}", err=True)
        sys.exit(1)


@cli.command(name='ai-analyze')
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--enable-ai-validation', is_flag=True, default=True, 
              help='Enable Phase 3 AI validation (default: enabled)')
@click.option('--consensus-strategy', type=click.Choice(['majority_vote', 'weighted_confidence']), 
              default='weighted_confidence', help='Multi-model consensus strategy')
@click.option('--output', '-o', type=click.Path(), help='Save complete results to JSON file')
@click.option('--show-details', is_flag=True, help='Show detailed AI analysis')
@click.pass_context
def ai_analyze(ctx, directory, enable_ai_validation, consensus_strategy, output, show_details):
    """
    Complete AI-powered vulnerability analysis (Phases 1+2+3)
    
    Runs the complete vulnerability detection and validation pipeline:
    
    Phase 1: Entry Point Detection with risk assessment
    Phase 2: RAG-powered fix generation with Stack Overflow citations  
    Phase 3: AI validation with multi-model consensus
    
    Features:
    - Dynamic VRAM detection and optimization
    - Multi-model consensus for high confidence
    - Comprehensive fix quality analysis
    - Professional security reports
    
    Examples:
        ai-analyze /path/to/project
        ai-analyze . --output analysis_results.json
        ai-analyze ~/webapp --show-details --consensus-strategy majority_vote
    """
    import asyncio
    from ai_validation.integration.pipeline_orchestrator import PipelineOrchestrator
    from ai_validation.models.consensus_models import ConsensusStrategy
    
    click.echo(f"Starting complete AI vulnerability analysis: {directory}")
    click.echo(f"AI Validation: {'Enabled' if enable_ai_validation else 'Disabled'}")
    click.echo(f"Consensus Strategy: {consensus_strategy}")
    
    try:
        # Map consensus strategy
        strategy_map = {
            'majority_vote': ConsensusStrategy.MAJORITY_VOTE,
            'weighted_confidence': ConsensusStrategy.WEIGHTED_CONFIDENCE
        }
        
        # Initialize pipeline orchestrator
        orchestrator = PipelineOrchestrator(
            enable_ai_validation=enable_ai_validation,
            consensus_strategy=strategy_map[consensus_strategy]
        )
        
        # Run complete analysis
        click.echo("\nInitiating complete vulnerability analysis pipeline...")
        
        # Run async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                orchestrator.analyze_project(directory, show_details=show_details)
            )
            
            if output:
                import json
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
                click.echo(f"Results saved to: {output}")
            
            # Display summary
            click.echo(f"\nAnalysis complete! Found {result.get('total_vulnerabilities', 0)} vulnerabilities")
            
        finally:
            loop.close()
            
    except Exception as e:
        click.echo(f"AI analysis failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(), required=True, 
              help='Output path for HTML report (e.g., security_report.html)')
@click.option('--enable-ai-validation', is_flag=True, default=True,
              help='Enable Phase 3 AI validation (default: enabled)')
@click.option('--title', type=str, help='Custom report title')
@click.pass_context  
def generate_report(ctx, directory, output, enable_ai_validation, title):
    """
    Generate comprehensive HTML security report (Complete Phase 1-4 Pipeline)
    
    Runs the complete 4-phase vulnerability analysis pipeline and generates
    a professional HTML report with:
    
    ✅ Phase 1: Entry Point Detection with risk assessment
    ✅ Phase 2: RAG-powered fix generation with Stack Overflow citations
    ✅ Phase 3: AI validation with confidence scoring (optional)
    ✅ Phase 4: Beautiful HTML report with CSS/JS, ASCII art, and interactivity
    
    Features:
    - Comprehensive vulnerability analysis across multiple languages
    - Evidence-backed fixes with Stack Overflow citations
    - AI-powered validation and confidence scoring
    - Interactive HTML report with search, charts, and animations
    - Professional styling with risk breakdowns and recommendations
    
    Examples:
        generate-report /path/to/project --output security_report.html
        generate-report . --output report.html --title "My App Security Analysis"
        generate-report ~/webapp --output report.html --enable-ai-validation
    """
    
    click.echo("COMPLETE SECURITY ANALYSIS PIPELINE")
    click.echo("=" * 60)
    click.echo("Phase 1-4: Entry Points → RAG Analysis → AI Validation → HTML Report")
    click.echo(f"Target: {directory}")
    click.echo(f"Output: {output}")
    click.echo(f"AI Validation: {'Enabled' if enable_ai_validation else 'Disabled'}")
    
    try:
        from report_generator.report_pipeline import CompletePipeline
        
        # Initialize pipeline
        pipeline = CompletePipeline()
        
        # Set custom title if provided
        if not title:
            title = f"Security Analysis - {directory.name}"
        
        # Run complete pipeline
        click.echo("\nStarting complete analysis pipeline...")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(
                pipeline.analyze_and_generate_report(
                    target_path=directory,
                    output_path=Path(output),
                    enable_ai_validation=enable_ai_validation
                )
            )
            
            click.echo(f"\nCOMPLETE ANALYSIS SUCCESSFUL!")
            click.echo("=" * 50)
            click.echo(f"Report ID: {report.report_id}")
            click.echo(f"HTML Report: {output}")
            click.echo(f"Vulnerabilities: {len(report.vulnerabilities)}")
            click.echo(f"Stack Overflow Citations: {report.stack_overflow_citations_count}")
            click.echo(f"Total Time: {report.scan_duration:.2f} seconds")
            click.echo(f"Risk Score: {report.get_risk_score():.0f}/100")
            
            # Display top findings
            top_vulns = report.get_top_vulnerabilities(3)
            if top_vulns:
                click.echo(f"\nTop Priority Issues:")
                for i, vuln in enumerate(top_vulns, 1):
                    click.echo(f"  {i}. {vuln.title} ({vuln.file_path}:{vuln.line_start})")
            
            click.echo(f"\nOpen the HTML report in your browser to view the complete analysis!")
            
        finally:
            loop.close()
        
    except ImportError as e:
        click.echo(f"Report generator not available: {e}")
        click.echo("Please ensure all dependencies are installed")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Report generation failed: {e}")
        import traceback
        if ctx.obj and ctx.obj.get('verbose'):
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='validate-fix')
@click.argument('file_path', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.argument('function_name')
@click.argument('project_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--show-reasoning', is_flag=True, help='Show detailed AI reasoning')
@click.pass_context  
def validate_fix(ctx, file_path, function_name, project_path, show_reasoning):
    """
    Validate a specific vulnerability fix using AI analysis
    
    Performs targeted AI validation of a single vulnerability and its fix:
    - Vulnerability verification with confidence scoring
    - Fix quality analysis (security, implementation, completeness)
    - Multi-model consensus for reliability
    
    Arguments:
        FILE_PATH: Path to the vulnerable file (relative to project)
        FUNCTION_NAME: Name of the function containing the vulnerability
        PROJECT_PATH: Root path of the project
    
    Examples:
        validate-fix app.py login_user /path/to/project
        validate-fix routes/auth.py authenticate . --show-reasoning
    """
    import asyncio
    from ai_validation.integration.pipeline_orchestrator import PipelineOrchestrator
    
    click.echo(f"Validating vulnerability fix:")
    click.echo(f"   File: {file_path}")
    click.echo(f"   Function: {function_name}")
    click.echo(f"   Project: {project_path}")
    
    try:
        # Initialize pipeline orchestrator  
        orchestrator = PipelineOrchestrator(enable_ai_validation=True)
        
        # Run single vulnerability analysis
        async def run_validation():
            return await orchestrator.analyze_single_vulnerability(
                file_path, function_name, project_path
            )
        
        results = asyncio.run(run_validation())
        
        # Display targeted validation results
        display_fix_validation_results(results, show_reasoning)
        
    except Exception as e:
        click.echo(f"Error during fix validation: {e}", err=True)
        if ctx.obj['debug']:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='system-status')
@click.pass_context
def system_status(ctx):
    """
    Check system status and AI capabilities
    
    Shows:
    - GPU/CPU specifications and VRAM availability
    - AI model availability and loading status
    - Pipeline component health
    - Performance recommendations
    """
    click.echo("SYSTEM STATUS CHECK")
    click.echo("=" * 50)
    
    try:
        # Check GPU/VRAM
        import subprocess
        import torch
        
        # GPU Detection
        click.echo("HARDWARE DETECTION:")
        try:
            gpu_info = subprocess.check_output(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader,nounits'], 
                                             stderr=subprocess.DEVNULL).decode().strip()
            if gpu_info:
                gpu_name, vram_mb = gpu_info.split(', ')
                vram_gb = float(vram_mb) / 1024
                click.echo(f"  GPU: {gpu_name}")
                click.echo(f"  VRAM: {vram_gb:.1f}GB")
                
                if vram_gb >= 8:
                    click.echo("  ✅ Recommendation: Local AI processing optimal")
                elif vram_gb >= 4:
                    click.echo("  Recommendation: Local AI with hybrid CPU+GPU")
                else:
                    click.echo("  Recommendation: API-based processing preferred")
            else:
                click.echo("  No NVIDIA GPU detected")
        except (subprocess.CalledProcessError, FileNotFoundError):
            click.echo("  No NVIDIA GPU detected or nvidia-smi unavailable")
        
        # PyTorch CUDA availability
        click.echo(f"  PyTorch CUDA: {'Available' if torch.cuda.is_available() else 'Not available'}")
        
        # Pipeline status
        click.echo("\nAI PIPELINE STATUS:")
        from ai_validation.integration.pipeline_orchestrator import PipelineOrchestrator
        
        orchestrator = PipelineOrchestrator(enable_ai_validation=True)
        status = orchestrator.get_system_status()
        
        for component, state in status.items():
            if isinstance(state, dict):
                click.echo(f"  {component}: Complex status")
            else:
                status_emoji = "OK" if state == "operational" else "ERROR"
                click.echo(f"  {component}: {status_emoji} {state}")
        
        click.echo("\n📈 PERFORMANCE ESTIMATE:")
        # Estimate based on GPU
        try:
            if torch.cuda.is_available():
                gpu_props = torch.cuda.get_device_properties(0)
                vram_gb = gpu_props.total_memory / (1024**3)
                
                if vram_gb >= 8:
                    click.echo("  Expected analysis time: 1-3 seconds per vulnerability")
                    click.echo("  Model capability: 13B parameter models supported")
                elif vram_gb >= 4:
                    click.echo("  Expected analysis time: 3-8 seconds per vulnerability") 
                    click.echo("  Model capability: 7B parameter models with hybrid processing")
                else:
                    click.echo("  Expected analysis time: 10-30 seconds per vulnerability")
                    click.echo("  Model capability: Limited local processing")
            else:
                click.echo("  Expected analysis time: 30+ seconds per vulnerability")
                click.echo("  Model capability: CPU-only processing (slow)")
        except Exception:
            click.echo("  Performance estimation unavailable")
        
    except Exception as e:
        click.echo(f"Error checking system status: {e}", err=True)
        if ctx.obj['debug']:
            import traceback
            traceback.print_exc()


@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--type', 'file_type', type=click.Choice([ft.value for ft in FileType]), 
              help='Filter by specific file type')
@click.option('--size-threshold', type=int, default=1024, help='Minimum file size to display')
@click.pass_context
def analyze(ctx, directory, file_type, size_threshold):
    """
    Perform detailed analysis of discovered files
    
    Shows file statistics, largest files, and distribution by type.
    """
    navigator = CLINavigator(show_progress=not ctx.obj.get('verbose', False))
    
    click.echo(f"Analyzing files in: {directory}")
    
    try:
        result = navigator.scan_directory(directory)
        
        # Overall statistics
        click.echo("\n📈 ANALYSIS RESULTS")
        click.echo("=" * 50)
        click.echo(result.get_summary())
        
        # File type filter
        if file_type:
            target_type = FileType(file_type)
            files = result.files_by_type[target_type]
            click.echo(f"\n🔍 {file_type.upper()} Files ({len(files)} found):")
            
            for file_info in sorted(files, key=lambda f: f.size, reverse=True)[:10]:
                if file_info.size >= size_threshold:
                    size_kb = file_info.size / 1024
                    click.echo(f"  {file_info.path.name:<30} {size_kb:>8.1f} KB")
        
        # Show largest files overall
        all_files = []
        for files in result.files_by_type.values():
            all_files.extend(files)
        
        largest_files = sorted(all_files, key=lambda f: f.size, reverse=True)[:10]
        
        click.echo(f"\nLargest Files:")
        for file_info in largest_files:
            if file_info.size >= size_threshold:
                size_kb = file_info.size / 1024
                click.echo(f"  {file_info.path.name:<30} {size_kb:>8.1f} KB  [{file_info.file_type.value}]")
        
        # Show errors if any
        if result.errors:
            click.echo(f"\nErrors encountered ({len(result.errors)}):")
            for error in result.errors[:5]:  # Show first 5 errors
                click.echo(f"  {error}")
            if len(result.errors) > 5:
                click.echo(f"  ... and {len(result.errors) - 5} more errors")
    
    except Exception as e:
        click.echo(f"❌ Error during analysis: {e}", err=True)
        sys.exit(1)


def display_entry_point_analysis(report: EntryPointReport, framework_filter: str, 
                                 risk_filter: str, show_paths: bool):
    """Display comprehensive entry point analysis results"""
    click.echo("\n🎯 ENTRY POINT ANALYSIS RESULTS")
    click.echo("=" * 60)
    
    # Summary statistics
    click.echo(f"Analysis Summary:")
    click.echo(f"  Target: {report.target_directory}")
    click.echo(f"  Duration: {report.scan_duration:.2f}s")
    click.echo(f"  Total Entry Points: {report.total_entry_points}")
    click.echo(f"  Frameworks Detected: {', '.join(report.frameworks_detected) if report.frameworks_detected else 'None'}")
    
    # Risk distribution
    click.echo(f"\n🚦 Risk Distribution:")
    click.echo(f"  🔴 High Risk: {report.high_risk_count}")
    click.echo(f"  🟡 Moderate Risk: {report.moderate_risk_count}")
    click.echo(f"  🟢 Low Risk: {report.low_risk_count}")
    
    # Filter and display entry points
    filtered_entry_points = filter_entry_points(report.all_entry_points, framework_filter, risk_filter)
    
    if not filtered_entry_points:
        click.echo(f"\n❌ No entry points match filters (framework: {framework_filter}, risk: {risk_filter})")
        return
    
    # Display high-risk entry points first
    high_risk_eps = [ep for ep in filtered_entry_points if ep.risk_level == RiskLevel.HIGH]
    if high_risk_eps:
        click.echo(f"\n🔴 HIGH RISK ENTRY POINTS ({len(high_risk_eps)}):")
        for ep in sorted(high_risk_eps, key=lambda x: x.risk_score, reverse=True):
            display_entry_point_summary(ep, show_paths)
    
    # Display moderate-risk entry points
    moderate_risk_eps = [ep for ep in filtered_entry_points if ep.risk_level == RiskLevel.MODERATE]
    if moderate_risk_eps and risk_filter in ['all', 'moderate']:
        click.echo(f"\n🟡 MODERATE RISK ENTRY POINTS ({len(moderate_risk_eps)}):")
        for ep in sorted(moderate_risk_eps, key=lambda x: x.risk_score, reverse=True)[:5]:
            display_entry_point_summary(ep, show_paths)
        if len(moderate_risk_eps) > 5:
            click.echo(f"    ... and {len(moderate_risk_eps) - 5} more moderate risk entry points")
    
    # Display low-risk summary
    low_risk_eps = [ep for ep in filtered_entry_points if ep.risk_level == RiskLevel.LOW]
    if low_risk_eps and risk_filter in ['all', 'low']:
        click.echo(f"\n🟢 LOW RISK ENTRY POINTS: {len(low_risk_eps)} found")
        if risk_filter == 'low':
            for ep in low_risk_eps[:3]:
                display_entry_point_summary(ep, show_paths)


def display_entry_point_summary(entry_point, show_paths: bool):
    """Display a summary of a single entry point"""
    path_str = str(entry_point.file_path) if show_paths else entry_point.file_path.name
    
    click.echo(f"  {entry_point.function_name} ({entry_point.framework or 'unknown'})")
    click.echo(f"     File: {path_str}")
    click.echo(f"     Type: {entry_point.entry_type.value}")
    click.echo(f"     Risk Score: {entry_point.risk_score}/100")
    
    if entry_point.route_info:
        methods = ",".join(entry_point.route_info.http_methods)
        click.echo(f"     Route: {methods} {entry_point.route_info.url_pattern}")
    
    if entry_point.external_input_count > 0:
        click.echo(f"     External Inputs: {entry_point.external_input_count}")
    
    if entry_point.risk_factors:
        click.echo(f"     Risk Factors: {', '.join(entry_point.risk_factors[:2])}")
    
    click.echo()


def display_risk_assessment(report: EntryPointReport, framework_filter: str, 
                           high_risk_only: bool, show_details: bool, output_format: str):
    """Display risk assessment results"""
    filtered_eps = filter_entry_points(
        report.all_entry_points, 
        framework_filter, 
        'high' if high_risk_only else 'all'
    )
    
    if output_format == 'json':
        display_risk_assessment_json(filtered_eps)
    elif output_format == 'summary':
        display_risk_assessment_summary(report)
    else:  # table format
        display_risk_assessment_table(filtered_eps, show_details)


def display_risk_assessment_table(entry_points, show_details: bool):
    """Display risk assessment in table format"""
    if not entry_points:
        click.echo("❌ No entry points to assess")
        return
    
    click.echo("\nBUSINESS IMPACT RISK ASSESSMENT")
    click.echo("=" * 80)
    
    # Table header
    header = f"{'Function':<25} {'Framework':<10} {'Risk':<10} {'Score':<6} {'Key Risk Factors':<30}"
    click.echo(header)
    click.echo("-" * 80)
    
    # Sort by risk score
    sorted_eps = sorted(entry_points, key=lambda x: (x.risk_level.value, x.risk_score), reverse=True)
    
    for ep in sorted_eps:
        risk_emoji = {"high": "🔴", "moderate": "🟡", "low": "🟢"}[ep.risk_level.value]
        framework = ep.framework or "unknown"
        risk_factors = ", ".join(ep.risk_factors[:2]) if ep.risk_factors else "None"
        
        row = f"{ep.function_name[:24]:<25} {framework[:9]:<10} {risk_emoji} {ep.risk_level.value:<6} {ep.risk_score:<6} {risk_factors[:29]:<30}"
        click.echo(row)
        
        if show_details:
            # Show additional details
            if ep.route_info:
                methods = ",".join(ep.route_info.http_methods)
                click.echo(f"    Route: {methods} {ep.route_info.url_pattern}")
            
            if ep.input_sources:
                inputs = [f"{src.source_type.value}:{src.variable_name}" for src in ep.input_sources[:3]]
                click.echo(f"    Inputs: {', '.join(inputs)}")
            
            security_issues = []
            if ep.external_input_count > 0 and not ep.input_validation_present:
                security_issues.append("No input validation")
            if ep.database_access and not ep.authentication_required:
                security_issues.append("Unauthenticated DB access")
            if security_issues:
                click.echo(f"    Issues: {', '.join(security_issues)}")
            click.echo()


def display_risk_assessment_summary(report: EntryPointReport):
    """Display executive summary of risk assessment"""
    click.echo("\nEXECUTIVE RISK SUMMARY")
    click.echo("=" * 40)
    
    attack_surface_score = report.get_attack_surface_score()
    
    click.echo(f"Overall Attack Surface Score: {attack_surface_score:.2f}/1.0")
    
    if attack_surface_score > 0.7:
        risk_level = "🔴 HIGH"
        recommendation = "Immediate security review recommended"
    elif attack_surface_score > 0.4:
        risk_level = "🟡 MODERATE" 
        recommendation = "Security improvements needed"
    else:
        risk_level = "🟢 LOW"
        recommendation = "Good security posture"
    
    click.echo(f"Risk Level: {risk_level}")
    click.echo(f"Recommendation: {recommendation}")
    
    # Top concerns
    high_risk_eps = [ep for ep in report.all_entry_points if ep.risk_level == RiskLevel.HIGH]
    if high_risk_eps:
        click.echo(f"\n🚨 Top Security Concerns:")
        for ep in sorted(high_risk_eps, key=lambda x: x.risk_score, reverse=True)[:3]:
            click.echo(f"  • {ep.function_name}: {', '.join(ep.risk_factors[:2])}")


def display_risk_assessment_json(entry_points):
    """Display risk assessment in JSON format"""
    import json
    
    data = {
        "entry_points": [],
        "summary": {
            "total": len(entry_points),
            "high_risk": len([ep for ep in entry_points if ep.risk_level == RiskLevel.HIGH]),
            "moderate_risk": len([ep for ep in entry_points if ep.risk_level == RiskLevel.MODERATE]),
            "low_risk": len([ep for ep in entry_points if ep.risk_level == RiskLevel.LOW])
        }
    }
    
    for ep in entry_points:
        ep_data = {
            "function_name": ep.function_name,
            "file_path": str(ep.file_path),
            "framework": ep.framework,
            "entry_type": ep.entry_type.value,
            "risk_level": ep.risk_level.value,
            "risk_score": ep.risk_score,
            "risk_factors": ep.risk_factors,
            "external_input_count": ep.external_input_count,
            "authentication_required": ep.authentication_required,
            "database_access": ep.database_access
        }
        
        if ep.route_info:
            ep_data["route"] = {
                "url_pattern": ep.route_info.url_pattern,
                "http_methods": ep.route_info.http_methods
            }
        
        data["entry_points"].append(ep_data)
    
    click.echo(json.dumps(data, indent=2))


def display_framework_analysis(report: EntryPointReport):
    """Display framework analysis results"""
    click.echo("\nFRAMEWORK ANALYSIS")
    click.echo("=" * 40)
    
    if not report.frameworks_detected:
        click.echo("❌ No frameworks detected")
        return
    
    for framework in report.frameworks_detected:
        framework_eps = [ep for ep in report.all_entry_points if ep.framework == framework]
        
        click.echo(f"\n📦 {framework.upper()} Framework:")
        click.echo(f"  Entry Points: {len(framework_eps)}")
        
        # Risk breakdown for this framework
        high_risk = len([ep for ep in framework_eps if ep.risk_level == RiskLevel.HIGH])
        moderate_risk = len([ep for ep in framework_eps if ep.risk_level == RiskLevel.MODERATE])
        low_risk = len([ep for ep in framework_eps if ep.risk_level == RiskLevel.LOW])
        
        click.echo(f"  Risk Distribution: 🔴 {high_risk}, 🟡 {moderate_risk}, 🟢 {low_risk}")
        
        # Show top risky entry points for this framework
        risky_eps = [ep for ep in framework_eps if ep.risk_level in [RiskLevel.HIGH, RiskLevel.MODERATE]]
        if risky_eps:
            click.echo("  Top Concerns:")
            for ep in sorted(risky_eps, key=lambda x: x.risk_score, reverse=True)[:3]:
                click.echo(f"    • {ep.function_name} (Score: {ep.risk_score})")


def filter_entry_points(entry_points, framework_filter: str, risk_filter: str):
    """Filter entry points by framework and risk level"""
    filtered = entry_points
    
    # Filter by framework
    if framework_filter != 'all':
        filtered = [ep for ep in filtered if ep.framework == framework_filter]
    
    # Filter by risk level
    if risk_filter != 'all':
        risk_level_map = {
            'high': RiskLevel.HIGH,
            'moderate': RiskLevel.MODERATE, 
            'low': RiskLevel.LOW
        }
        if risk_filter in risk_level_map:
            filtered = [ep for ep in filtered if ep.risk_level == risk_level_map[risk_filter]]
    
    return filtered


def detect_frameworks_only(scan_result: ScanResult, detector: EntryPointDetector):
    """Quick framework detection without full analysis"""
    frameworks_found = {}
    
    analyzable_types = [FileType.PYTHON, FileType.JAVASCRIPT, FileType.TYPESCRIPT]
    
    for file_type in analyzable_types:
        if file_type in scan_result.files_by_type:
            for file_info in scan_result.files_by_type[file_type]:
                for framework_name, framework_detector in detector.framework_detectors.items():
                    if framework_detector.detect_framework(file_info):
                        if framework_name not in frameworks_found:
                            frameworks_found[framework_name] = []
                        frameworks_found[framework_name].append(file_info.path)
    
    return frameworks_found


def display_framework_detection(frameworks):
    """Display framework detection results"""
    if not frameworks:
        click.echo("❌ No frameworks detected")
        return
    
    click.echo(f"\n✅ Detected {len(frameworks)} framework(s):")
    
    for framework, files in frameworks.items():
        click.echo(f"\n📦 {framework.upper()}:")
        click.echo(f"  Files: {len(files)}")
        for file_path in files[:5]:  # Show first 5 files
            click.echo(f"    • {file_path.name}")
        if len(files) > 5:
            click.echo(f"    ... and {len(files) - 5} more files")


def save_entry_point_report(report: EntryPointReport, output_path: str):
    """Save detailed entry point report to file"""
    with open(output_path, 'w') as f:
        f.write(report.get_summary())
        f.write("\n\nDETAILED ENTRY POINT ANALYSIS\n")
        f.write("=" * 60 + "\n")
        
        for ep in sorted(report.all_entry_points, key=lambda x: x.risk_score, reverse=True):
            f.write(f"\n{ep.get_risk_summary()}")
            f.write(f"File: {ep.file_path}\n")
            f.write(f"Type: {ep.entry_type.value}\n")
            f.write(f"Framework: {ep.framework or 'Unknown'}\n")
            
            if ep.route_info:
                f.write(f"Route: {ep.route_info}\n")
            
            if ep.input_sources:
                f.write(f"Input Sources ({len(ep.input_sources)}):\n")
                for src in ep.input_sources:
                    f.write(f"  • {src}\n")
            
            if ep.security_features:
                f.write("Security Features:\n")
                for feature in ep.security_features:
                    f.write(f"  • {feature}\n")
            
            f.write("-" * 40 + "\n")


def display_ai_analysis_results(results: dict, show_details: bool):
    """Display complete AI analysis results"""
    if "error" in results:
        click.echo(f"❌ Analysis failed: {results['error']}")
        return
    
    summary = results.get("analysis_summary", {})
    timing = results.get("timing", {})
    
    click.echo("\nAI VULNERABILITY ANALYSIS COMPLETE")
    click.echo("=" * 60)
    
    # Summary
    click.echo(f"Analysis Summary:")
    click.echo(f"  Entry Points Found: {summary.get('total_entry_points', 0)}")
    click.echo(f"  Fixes Generated: {summary.get('total_fixes_generated', 0)}")
    click.echo(f"  AI Validations: {summary.get('total_validations', 0)}")
    
    # Timing
    click.echo(f"\n⏱️  Performance:")
    click.echo(f"  Phase 1 Detection: {timing.get('phase1_detection_seconds', 0):.2f}s")
    click.echo(f"  Phase 2 Fix Generation: {timing.get('phase2_fix_generation_seconds', 0):.2f}s")
    click.echo(f"  Phase 3 AI Validation: {timing.get('phase3_ai_validation_seconds', 0):.2f}s")
    click.echo(f"  Total Analysis Time: {timing.get('total_analysis_seconds', 0):.2f}s")
    
    # AI Validation Results
    ai_validation = results.get("ai_validation", {})
    if ai_validation:
        validation_summary = ai_validation.get("validation_summary", {})
        click.echo(f"\n🧠 AI Validation Summary:")
        click.echo(f"  Confirmed Vulnerabilities: {validation_summary.get('confirmed_vulnerabilities', 0)}")
        click.echo(f"  False Positives: {validation_summary.get('false_positives', 0)}")
        click.echo(f"  Average Fix Quality: {validation_summary.get('average_fix_quality_score', 0)}/100")
        click.echo(f"  Critical Issues: {validation_summary.get('critical_issues', 0)}")
        
        # Show detailed results if requested
        if show_details:
            validation_results = ai_validation.get("validation_results", [])
            if validation_results:
                click.echo(f"\n🔍 Detailed AI Validation Results:")
                for result in validation_results[:5]:  # Show first 5
                    confidence_emoji = "🔴" if result.get("overall_confidence", 0) >= 0.8 else "🟡" if result.get("overall_confidence", 0) >= 0.6 else "⚪"
                    click.echo(f"  {confidence_emoji} {result.get('function_name', 'Unknown')}")
                    click.echo(f"    Genuine Vulnerability: {result.get('is_genuine_vulnerability', False)}")
                    click.echo(f"    Fix Quality Score: {result.get('fix_quality_score', 0):.1f}/100")
                    click.echo(f"    Consensus Confidence: {result.get('consensus_confidence', 0):.2f}")
                    click.echo(f"    Recommendation: {result.get('recommendation', 'No recommendation')}")
                    click.echo()


def display_fix_validation_results(results: dict, show_reasoning: bool):
    """Display targeted fix validation results"""
    if "error" in results:
        click.echo(f"❌ Validation failed: {results['error']}")
        return
    
    ai_validation = results.get("ai_validation", {})
    if not ai_validation:
        click.echo("❌ No AI validation results available")
        return
    
    validation_results = ai_validation.get("validation_results", [])
    if not validation_results:
        click.echo("❌ No validation results found")
        return
    
    result = validation_results[0]  # Single vulnerability validation
    
    click.echo("\n🔍 VULNERABILITY FIX VALIDATION")
    click.echo("=" * 50)
    
    # Main assessment
    is_vulnerable = result.get("is_genuine_vulnerability", False)
    fix_quality = result.get("fix_quality_score", 0)
    consensus_confidence = result.get("consensus_confidence", 0)
    overall_confidence = result.get("overall_confidence", 0)
    
    vulnerability_status = "🔴 CONFIRMED VULNERABILITY" if is_vulnerable else "✅ FALSE POSITIVE"
    click.echo(f"Vulnerability Status: {vulnerability_status}")
    click.echo(f"Overall Confidence: {overall_confidence:.1%}")
    click.echo(f"Fix Quality Score: {fix_quality:.1f}/100")
    click.echo(f"Consensus Confidence: {consensus_confidence:.1%}")
    
    # Recommendation
    recommendation = result.get("recommendation", "No recommendation available")
    click.echo(f"\n📋 Recommendation:")
    click.echo(f"  {recommendation}")
    
    # Detailed reasoning if requested
    if show_reasoning:
        ai_reasoning = result.get("ai_reasoning", "")
        fix_recommendations = result.get("fix_recommendations", [])
        uncertainty_flag = result.get("uncertainty_flag", False)
        
        if ai_reasoning:
            click.echo(f"\n🧠 AI Reasoning:")
            click.echo(f"  {ai_reasoning}")
        
        if fix_recommendations:
            click.echo(f"\n💡 Fix Improvement Recommendations:")
            for i, rec in enumerate(fix_recommendations, 1):
                click.echo(f"  {i}. {rec}")
        
        if uncertainty_flag:
            click.echo(f"\nUNCERTAINTY WARNING: AI models showed disagreement or low confidence")
            click.echo(f"   Manual security review is strongly recommended for this case")


def save_ai_results_to_file(results: dict, output_path: str):
    """Save complete AI analysis results to JSON file"""
    import json
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def save_results_to_file(result: ScanResult, output_path: str):
    """Save detailed scan results to a file"""
    with open(output_path, 'w') as f:
        f.write(result.get_summary())
        f.write("\n\nDETAILED FILE LISTING:\n")
        f.write("=" * 50 + "\n")
        
        for file_type, files in result.files_by_type.items():
            if files:
                f.write(f"\n{file_type.value.upper()} FILES ({len(files)}):\n")
                for file_info in files:
                    size_kb = file_info.size / 1024
                    entry_marker = " [ENTRY POINT]" if file_info.is_entry_point_candidate else ""
                    f.write(f"  {file_info.path} ({size_kb:.1f} KB){entry_marker}\n")
        
        if result.errors:
            f.write(f"\nERRORS ({len(result.errors)}):\n")
            for error in result.errors:
                f.write(f"  {error}\n")


def main():
    """Main entry point for the CLI application"""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        click.echo(f"\n❌ Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()