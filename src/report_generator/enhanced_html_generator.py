"""
Enhanced HTML Report Generator - Modern Dark Theme with Professional Styling
Integrates with Phase 4 pipeline while maintaining the clean black background aesthetic
"""

import os
import html
import json
from datetime import datetime
from typing import Dict, Any, List, Union, Optional, Tuple
from pathlib import Path

from .models import SecurityReport, VulnerabilityFinding, RiskLevel, VulnerabilityCategory


class EnhancedHTMLGenerator:
    """Enhanced HTML generator with modern dark theme and professional styling"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        
    def generate_enhanced_report(self, report: SecurityReport, output_path: Path) -> Path:
        """Generate enhanced HTML report with modern dark theme"""
        
        # Generate the complete HTML content
        html_content = self._generate_enhanced_html_content(report)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[SUCCESS] Enhanced security report generated: {output_path}")
        return output_path
    
    def _generate_enhanced_html_content(self, report: SecurityReport) -> str:
        """Generate complete enhanced HTML content with dark theme"""
        
        css = self._generate_enhanced_css()
        js = self._generate_enhanced_javascript()
        ascii_art = self._generate_professional_ascii_art()
        header = self._generate_enhanced_header(report)
        dashboard = self._generate_dashboard(report)
        vulnerability_details = self._generate_enhanced_vulnerability_details(report)
        file_analysis = self._generate_enhanced_file_analysis(report)
        recommendations = self._generate_enhanced_recommendations(report)
        technical_appendix = self._generate_technical_appendix(report)
        
        # Combine into complete HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {report.title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>{css}</style>
</head>
<body>
    <div class="report-container">
        {ascii_art}
        {header}
        {dashboard}
        {vulnerability_details}
        {file_analysis}
        {recommendations}
        {technical_appendix}
    </div>
    
    <script>{js}</script>
</body>
</html>"""
        
        return html
    
    def _generate_professional_ascii_art(self) -> str:
        """Generate professional ASCII art header"""
        return """
<div class="ascii-header">
<pre class="ascii-art">
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
                                                                
          ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗    
          ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    
          ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║       
          ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║       
          ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║       
          ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       
</pre>
<div class="ascii-subtitle">AI-Powered Vulnerability Analysis with Stack Overflow Citations</div>
</div>"""
    
    def _generate_enhanced_header(self, report: SecurityReport) -> str:
        """Generate enhanced header with modern styling"""
        return f"""
<div class="report-header">
    <div class="header-content">
        <div class="header-left">
            <h1 class="report-title">[SECURITY] Security Analysis Report</h1>
            <div class="report-subtitle">{report.title}</div>
            <div class="report-meta">
                <div class="meta-group">
                    <div class="meta-item">
                        <span class="meta-label">Report ID:</span>
                        <span class="meta-value">{report.report_id}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Generated:</span>
                        <span class="meta-value">{report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                    </div>
                </div>
                <div class="meta-group">
                    <div class="meta-item">
                        <span class="meta-label">Target:</span>
                        <span class="meta-value">{report.target_path}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Duration:</span>
                        <span class="meta-value">{report.scan_duration:.2f}s</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="header-right">
            <div class="risk-gauge-container">
                <div class="risk-gauge" data-score="{report.get_risk_score():.1f}">
                    <div class="gauge-fill"></div>
                    <div class="gauge-center">
                        <div class="gauge-score">{report.get_risk_score():.0f}</div>
                        <div class="gauge-label">Risk Score</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>"""
    
    def _generate_dashboard(self, report: SecurityReport) -> str:
        """Generate modern dashboard with key metrics"""
        
        critical_high = report.get_critical_and_high_count()
        total_vulns = report.get_total_vulnerabilities()
        
        # Risk assessment
        if critical_high > 10:
            risk_status = "[CRITICAL] CRITICAL ATTENTION REQUIRED"
            risk_class = "critical"
        elif critical_high > 5:
            risk_status = "[HIGH] HIGH RISK DETECTED"
            risk_class = "high"
        elif critical_high > 0:
            risk_status = "[MEDIUM] MODERATE RISK"
            risk_class = "medium"
        else:
            risk_status = "[LOW] LOW RISK"
            risk_class = "low"
        
        return f"""
<div class="dashboard">
    <div class="dashboard-header">
        <h2>[DASHBOARD] Executive Dashboard</h2>
        <div class="risk-status risk-{risk_class}">{risk_status}</div>
    </div>
    
    <div class="dashboard-grid">
        <div class="metric-card primary">
            <div class="metric-icon">[SEARCH]</div>
            <div class="metric-content">
                <div class="metric-value">{total_vulns}</div>
                <div class="metric-label">Total Vulnerabilities</div>
            </div>
        </div>
        
        <div class="metric-card danger">
            <div class="metric-icon">[ALERT]</div>
            <div class="metric-content">
                <div class="metric-value">{critical_high}</div>
                <div class="metric-label">Critical & High Priority</div>
            </div>
        </div>
        
        <div class="metric-card info">
            <div class="metric-icon">[INFO]</div>
            <div class="metric-content">
                <div class="metric-value">{report.stack_overflow_citations_count}</div>
                <div class="metric-label">Stack Overflow Citations</div>
            </div>
        </div>
        
        <div class="metric-card success">
            <div class="metric-icon">[AI]</div>
            <div class="metric-content">
                <div class="metric-value">{'[ENABLED]' if report.ai_analysis_enabled else '[DISABLED]'}</div>
                <div class="metric-label">AI Validation</div>
            </div>
        </div>
        
        <div class="metric-card warning">
            <div class="metric-icon">[FILES]</div>
            <div class="metric-content">
                <div class="metric-value">{report.total_files_scanned}</div>
                <div class="metric-label">Files Scanned</div>
            </div>
        </div>
        
        <div class="metric-card secondary">
            <div class="metric-icon">[SPEED]</div>
            <div class="metric-content">
                <div class="metric-value">{len(report.phases_completed)}/4</div>
                <div class="metric-label">Phases Complete</div>
            </div>
        </div>
    </div>
    
    <div class="risk-breakdown-chart">
        <h3>[TARGET] Vulnerability Distribution</h3>
        {self._generate_enhanced_risk_chart(report)}
    </div>
</div>"""
    
    def _generate_enhanced_risk_chart(self, report: SecurityReport) -> str:
        """Generate enhanced risk distribution chart"""
        total = report.get_total_vulnerabilities()
        if total == 0:
            return "<div class='no-data'>No vulnerabilities detected</div>"
        
        chart_html = '<div class="risk-chart-modern">'
        
        risk_data = [
            (RiskLevel.CRITICAL, "[CRITICAL]", "#dc2626"),
            (RiskLevel.HIGH, "[HIGH]", "#ea580c"),
            (RiskLevel.MEDIUM, "[MEDIUM]", "#d97706"),
            (RiskLevel.LOW, "[LOW]", "#16a34a"),
            (RiskLevel.INFO, "[INFO]", "#2563eb")
        ]
        
        for risk_level, emoji, color in risk_data:
            count = report.vulnerability_counts.get(risk_level, 0)
            if count > 0:
                percentage = (count / total * 100)
                chart_html += f"""
                <div class="risk-bar-modern">
                    <div class="risk-label-modern">
                        <span class="risk-emoji">{emoji}</span>
                        <span class="risk-name">{risk_level.value.upper()}</span>
                    </div>
                    <div class="risk-progress-container">
                        <div class="risk-progress-bar" style="width: {percentage}%; background-color: {color}"></div>
                    </div>
                    <div class="risk-count-modern">{count}</div>
                </div>"""
        
        chart_html += '</div>'
        return chart_html
    
    def _generate_enhanced_vulnerability_details(self, report: SecurityReport) -> str:
        """Generate enhanced vulnerability details section"""
        
        # Group vulnerabilities by priority
        critical_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.CRITICAL]
        high_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.HIGH]
        medium_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.MEDIUM]
        
        html = """
<div class="vulnerability-section">
    <div class="section-header">
        <h2>[ANALYSIS] Vulnerability Analysis</h2>
        <div class="section-subtitle">Detailed security findings with evidence-based remediation</div>
    </div>
"""
        
        # Critical vulnerabilities first
        if critical_vulns:
            html += self._generate_enhanced_vuln_group("[CRITICAL] Critical Priority", critical_vulns, "critical")
        
        if high_vulns:
            html += self._generate_enhanced_vuln_group("[HIGH] High Priority", high_vulns, "high")
        
        if medium_vulns:
            html += self._generate_enhanced_vuln_group("[MEDIUM] Medium Priority", medium_vulns, "medium")
        
        html += "</div>"
        return html
    
    def _generate_enhanced_vuln_group(self, title: str, vulnerabilities: List[VulnerabilityFinding], risk_class: str) -> str:
        """Generate enhanced vulnerability group"""
        
        html = f"""
<div class="vuln-group vuln-group-{risk_class}">
    <div class="vuln-group-header">
        <h3>{title}</h3>
        <div class="vuln-count">{len(vulnerabilities)} vulnerabilities</div>
    </div>
    <div class="vuln-cards">
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            html += self._generate_enhanced_vuln_card(vuln, i)
        
        html += """
    </div>
</div>"""
        
        return html
    
    def _generate_enhanced_vuln_card(self, vuln: VulnerabilityFinding, index: int) -> str:
        """Generate enhanced vulnerability card"""
        
        # Stack Overflow citations
        citations_html = ""
        if vuln.stack_overflow_citations:
            citations_html = "<div class='citations-modern'><h5>[EVIDENCE] Evidence-Based Solutions:</h5><div class='citations-list'>"
            for citation in vuln.stack_overflow_citations:
                accepted_badge = "[ACCEPTED]" if citation.accepted_answer else ""
                citations_html += f"""
                <div class="citation-item">
                    <div class="citation-header">
                        <a href="{citation.url}" target="_blank" class="citation-link">
                            <strong>SO#{citation.question_id}:</strong> {citation.title}
                        </a>
                        {f'<span class="accepted-badge">{accepted_badge}</span>' if accepted_badge else ''}
                    </div>
                    <div class="citation-meta">
                        <span class="citation-score">[SCORE] {citation.score}</span>
                        <span class="citation-answers">[ANSWERS] {citation.answer_count}</span>
                        <span class="citation-relevance">[RELEVANCE] {citation.relevance_score:.0f}%</span>
                    </div>
                </div>"""
            citations_html += "</div></div>"
        
        # Code snippet with syntax highlighting
        code_html = ""
        if vuln.vulnerable_code:
            code_html = f"""
            <div class="code-section">
                <div class="code-header">
                    <span class="code-title">[VULNERABLE] Vulnerable Code</span>
                    <span class="code-location">{vuln.vulnerable_code.get_line_range()}</span>
                </div>
                <div class="code-content">
                    <pre><code class="language-{vuln.vulnerable_code.language}">{self._escape_html(vuln.vulnerable_code.content)}</code></pre>
                </div>
            </div>"""
        
        # Fix example
        fix_html = ""
        if vuln.fix_code_example:
            fix_html = f"""
            <div class="fix-section">
                <div class="fix-header">
                    <span class="fix-title">[FIX] Recommended Fix</span>
                </div>
                <div class="fix-content">
                    <pre><code class="language-{vuln.vulnerable_code.language if vuln.vulnerable_code else 'text'}">{self._escape_html(vuln.fix_code_example)}</code></pre>
                </div>
            </div>"""
        
        # AI Analysis
        ai_html = ""
        if vuln.ai_confidence > 0:
            confidence_class = "high" if vuln.ai_confidence >= 0.8 else "medium" if vuln.ai_confidence >= 0.6 else "low"
            ai_html = f"""
            <div class="ai-analysis-modern">
                <div class="ai-header">[AI] AI Analysis</div>
                <div class="ai-metrics-grid">
                    <div class="ai-metric">
                        <div class="ai-metric-label">Confidence</div>
                        <div class="ai-metric-value confidence-{confidence_class}">{vuln.ai_confidence:.1%}</div>
                    </div>
                    <div class="ai-metric">
                        <div class="ai-metric-label">False Positive Risk</div>
                        <div class="ai-metric-value">{vuln.false_positive_probability:.1%}</div>
                    </div>
                    <div class="ai-metric">
                        <div class="ai-metric-label">Business Impact</div>
                        <div class="ai-metric-value">{vuln.business_impact}</div>
                    </div>
                </div>
            </div>"""
        
        return f"""
<div class="vuln-card-modern" id="vuln-{vuln.vulnerability_id}">
    <div class="vuln-card-header">
        <div class="vuln-badge-container">
            <span class="vuln-index">#{index}</span>
            <span class="vuln-risk-badge risk-{vuln.risk_level.value}">{vuln.get_risk_emoji()}</span>
        </div>
        <div class="vuln-title-container">
            <h4 class="vuln-title">{vuln.title}</h4>
            <div class="vuln-meta">
                <span class="vuln-file">[FILE] {vuln.file_path}</span>
                <span class="vuln-line">[LINE] Line {vuln.line_start}</span>
                <span class="vuln-category">[CATEGORY] {vuln.category.value.replace('_', ' ').title()}</span>
            </div>
        </div>
    </div>
    
    <div class="vuln-card-body">
        <div class="vuln-description">
            {vuln.description}
        </div>
        
        {code_html}
        
        <div class="vuln-details-grid">
            <div class="detail-item">
                <span class="detail-label">CWE ID:</span>
                <span class="detail-value">{vuln.cwe_id or 'Not specified'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">OWASP:</span>
                <span class="detail-value">{vuln.owasp_category or 'Not mapped'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Function:</span>
                <span class="detail-value">{vuln.function_name or 'Global scope'}</span>
            </div>
        </div>
        
        {ai_html}
        
        {citations_html}
        
        {fix_html}
        
        <div class="remediation-modern">
            <div class="remediation-header">[REMEDIATION] Remediation Steps</div>
            <div class="remediation-content">{vuln.recommended_fix}</div>
        </div>
    </div>
</div>"""
    
    def _generate_enhanced_file_analysis(self, report: SecurityReport) -> str:
        """Generate enhanced file analysis section"""
        
        file_groups = report.get_vulnerabilities_by_file()
        
        html = """
<div class="file-analysis-section">
    <div class="section-header">
        <h2>[FILES] File-by-File Analysis</h2>
        <div class="section-subtitle">Security assessment organized by source files</div>
    </div>
    
    <div class="file-grid">
"""
        
        for file_path, vulnerabilities in file_groups.items():
            # Count vulnerabilities by risk level for this file
            risk_counts = {level: 0 for level in RiskLevel}
            for vuln in vulnerabilities:
                risk_counts[vuln.risk_level] += 1
            
            # Determine overall file risk level
            if risk_counts[RiskLevel.CRITICAL] > 0:
                file_risk = "critical"
            elif risk_counts[RiskLevel.HIGH] > 0:
                file_risk = "high"
            elif risk_counts[RiskLevel.MEDIUM] > 0:
                file_risk = "medium"
            else:
                file_risk = "low"
            
            html += f"""
            <div class="file-card file-risk-{file_risk}">
                <div class="file-header">
                    <div class="file-title">
                        <span class="file-icon">[FILE]</span>
                        <span class="file-name">{file_path.name}</span>
                    </div>
                    <div class="file-stats">
                        <span class="file-vuln-count">{len(vulnerabilities)}</span>
                        {self._generate_file_risk_indicators(risk_counts)}
                    </div>
                </div>
                
                <div class="file-vulns">
"""
            
            for vuln in vulnerabilities:
                html += f"""
                <div class="file-vuln-item">
                    <span class="vuln-dot risk-{vuln.risk_level.value}"></span>
                    <a href="#vuln-{vuln.vulnerability_id}" class="vuln-link">
                        Line {vuln.line_start}: {vuln.title}
                    </a>
                    <span class="vuln-category-tag">{vuln.category.value.replace('_', ' ').title()}</span>
                </div>"""
            
            html += """
                </div>
            </div>"""
        
        html += """
    </div>
</div>"""
        
        return html
    
    def _generate_file_risk_indicators(self, risk_counts: Dict[RiskLevel, int]) -> str:
        """Generate modern file risk indicators"""
        indicators = []
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = risk_counts[risk_level]
            if count > 0:
                indicators.append(f'<span class="risk-pill risk-{risk_level.value}">{count}</span>')
        
        return f'<div class="risk-pills">{"".join(indicators)}</div>'
    
    def _generate_enhanced_recommendations(self, report: SecurityReport) -> str:
        """Generate enhanced recommendations section"""
        
        top_vulns = report.get_top_vulnerabilities(5)
        
        html = """
<div class="recommendations-section">
    <div class="section-header">
        <h2>[RECOMMENDATIONS] Priority Recommendations</h2>
        <div class="section-subtitle">Actionable security improvements ranked by impact</div>
    </div>
    
    <div class="recommendations-grid">
"""
        
        for i, vuln in enumerate(top_vulns, 1):
            priority_class = f"priority-{min(i, 3)}"  # Max 3 priority levels for styling
            
            html += f"""
            <div class="recommendation-card {priority_class}">
                <div class="rec-header">
                    <div class="rec-priority">#{i}</div>
                    <div class="rec-title">{vuln.title}</div>
                </div>
                <div class="rec-content">
                    <div class="rec-impact">
                        <strong>Impact:</strong> {vuln.business_impact or 'Security vulnerability requiring immediate attention'}
                    </div>
                    <div class="rec-action">
                        <strong>Action:</strong> {vuln.recommended_fix}
                    </div>
                    <div class="rec-location">
                        <strong>Location:</strong> {vuln.file_path} (Line {vuln.line_start})
                    </div>
                    {f'<div class="rec-confidence"><strong>AI Confidence:</strong> {vuln.ai_confidence:.1%}</div>' if vuln.ai_confidence > 0 else ''}
                    {f'<div class="rec-evidence"><strong>Evidence:</strong> {len(vuln.stack_overflow_citations)} Stack Overflow citations</div>' if vuln.stack_overflow_citations else ''}
                </div>
            </div>"""
        
        html += """
    </div>
</div>"""
        
        return html
    
    def _generate_technical_appendix(self, report: SecurityReport) -> str:
        """Generate technical appendix"""
        
        report_data = {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "total_vulnerabilities": len(report.vulnerabilities),
            "vulnerability_counts": {level.value: count for level, count in report.vulnerability_counts.items()},
            "languages": [lang.language for lang in report.languages_detected],
            "frameworks": [fw.name for fw in report.frameworks_detected],
            "phases_completed": report.phases_completed
        }
        
        return f"""
<div class="technical-appendix">
    <div class="section-header">
        <h2>[TECHNICAL] Technical Appendix</h2>
        <div class="section-subtitle">Detailed technical information and metadata</div>
    </div>
    
    <div class="appendix-grid">
        <div class="appendix-card">
            <h3>[CONFIG] Analysis Configuration</h3>
            <div class="config-list">
                <div class="config-item">
                    <span class="config-label">Phases Completed:</span>
                    <span class="config-value">{len(report.phases_completed)}/4</span>
                </div>
                <div class="config-item">
                    <span class="config-label">AI Analysis:</span>
                    <span class="config-value">{'Enabled' if report.ai_analysis_enabled else 'Disabled'}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Scan Duration:</span>
                    <span class="config-value">{report.scan_duration:.2f}s</span>
                </div>
            </div>
        </div>
        
        <div class="appendix-card">
            <h3>[STATS] Analysis Statistics</h3>
            <div class="config-list">
                <div class="config-item">
                    <span class="config-label">Files Scanned:</span>
                    <span class="config-value">{report.total_files_scanned}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Lines of Code:</span>
                    <span class="config-value">{report.total_lines_scanned:,}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Languages:</span>
                    <span class="config-value">{len(report.languages_detected)}</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Frameworks:</span>
                    <span class="config-value">{len(report.frameworks_detected)}</span>
                </div>
            </div>
        </div>
        
        <div class="appendix-card">
            <h3>[TOOL] Tool Information</h3>
            <div class="config-list">
                <div class="config-item">
                    <span class="config-label">Tool:</span>
                    <span class="config-value">Code Security Analyzer v1.0</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Engine:</span>
                    <span class="config-value">AI-Powered with Local LLM</span>
                </div>
                <div class="config-item">
                    <span class="config-label">Citations:</span>
                    <span class="config-value">Stack Overflow Integration</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="raw-data-section">
        <h3>[DATA] Technical Data</h3>
        <details class="data-details">
            <summary>View Raw Report Data (JSON)</summary>
            <pre class="json-data"><code>{json.dumps(report_data, indent=2)}</code></pre>
        </details>
    </div>
</div>

<footer class="report-footer">
    <div class="footer-content">
        <div class="footer-left">
            <strong>[AI] Code Security Analyzer</strong> - AI-Powered Vulnerability Detection
        </div>
        <div class="footer-right">
            Report ID: {report.report_id} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
    </div>
</footer>"""
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters in text"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _generate_enhanced_css(self) -> str:
        """Generate enhanced CSS with modern dark theme"""
        return """
/* Enhanced Dark Theme CSS */
:root {
    --bg-primary: #0f1114;
    --bg-secondary: #1a1d21;
    --bg-tertiary: #252931;
    --bg-card: #2a2f36;
    --bg-hover: #333940;
    
    --text-primary: #ffffff;
    --text-secondary: #b4bcd0;
    --text-muted: #8b949e;
    
    --accent-primary: #3b82f6;
    --accent-secondary: #10b981;
    --accent-warning: #f59e0b;
    --accent-danger: #ef4444;
    --accent-info: #06b6d4;
    
    --border-primary: #383838;
    --border-secondary: #4a5568;
    
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --info: #3b82f6;
    
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 16px;
    
    --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
    --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
    --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.4);
    
    --transition-fast: 0.2s ease;
    --transition-normal: 0.3s ease;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: var(--text-primary);
    background: var(--bg-primary);
    font-size: 14px;
}

.report-container {
    min-height: 100vh;
}

/* ASCII Header */
.ascii-header {
    background: linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #0f1114 100%);
    padding: 2rem;
    text-align: center;
    border-bottom: 1px solid var(--border-primary);
}

.ascii-art {
    color: #00ff41;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 10px;
    line-height: 1.1;
    margin-bottom: 1rem;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
}

.ascii-subtitle {
    color: var(--text-secondary);
    font-size: 1rem;
    font-weight: 300;
}

/* Enhanced Header */
.report-header {
    background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
    padding: 3rem 2rem;
    border-bottom: 1px solid var(--border-primary);
}

.header-content {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 2rem;
}

.header-left {
    flex: 1;
}

.report-title {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.report-subtitle {
    font-size: 1.2rem;
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
}

.report-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
}

.meta-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.meta-item {
    display: flex;
    gap: 0.5rem;
}

.meta-label {
    color: var(--text-muted);
    min-width: 80px;
}

.meta-value {
    color: var(--text-primary);
    font-weight: 500;
}

/* Risk Gauge */
.risk-gauge-container {
    display: flex;
    justify-content: center;
    align-items: center;
}

.risk-gauge {
    width: 120px;
    height: 120px;
    position: relative;
    border-radius: 50%;
    background: conic-gradient(
        from 0deg,
        var(--success) 0deg 72deg,
        var(--warning) 72deg 144deg,
        var(--accent-warning) 144deg 216deg,
        var(--danger) 216deg 288deg,
        #dc2626 288deg 360deg
    );
    padding: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.gauge-center {
    width: 100%;
    height: 100%;
    background: var(--bg-card);
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
}

.gauge-score {
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--text-primary);
}

.gauge-label {
    font-size: 0.8rem;
    color: var(--text-muted);
}

/* Dashboard */
.dashboard {
    padding: 3rem 2rem;
    max-width: 1200px;
    margin: 0 auto;
    background: var(--bg-primary);
}

.dashboard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
}

.dashboard-header h2 {
    font-size: 2rem;
    font-weight: 600;
    color: var(--text-primary);
}

.risk-status {
    padding: 0.75rem 1.5rem;
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: 0.9rem;
}

.risk-status.risk-critical {
    background: rgba(239, 68, 68, 0.2);
    color: var(--danger);
    border: 1px solid var(--danger);
}

.risk-status.risk-high {
    background: rgba(245, 158, 11, 0.2);
    color: var(--warning);
    border: 1px solid var(--warning);
}

.risk-status.risk-medium {
    background: rgba(59, 130, 246, 0.2);
    color: var(--info);
    border: 1px solid var(--info);
}

.risk-status.risk-low {
    background: rgba(16, 185, 129, 0.2);
    color: var(--success);
    border: 1px solid var(--success);
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
}

.metric-card {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    box-shadow: var(--shadow-sm);
    border: 1px solid var(--border-primary);
    transition: var(--transition-normal);
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
    border-color: var(--border-secondary);
}

.metric-icon {
    font-size: 2rem;
    opacity: 0.8;
}

.metric-content {
    flex: 1;
}

.metric-value {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.25rem;
}

.metric-label {
    font-size: 0.85rem;
    color: var(--text-muted);
    font-weight: 500;
}

.metric-card.primary .metric-value { color: var(--accent-primary); }
.metric-card.danger .metric-value { color: var(--danger); }
.metric-card.success .metric-value { color: var(--success); }
.metric-card.warning .metric-value { color: var(--warning); }
.metric-card.info .metric-value { color: var(--info); }
.metric-card.secondary .metric-value { color: var(--text-secondary); }

/* Risk Chart */
.risk-breakdown-chart {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 2rem;
    border: 1px solid var(--border-primary);
}

.risk-breakdown-chart h3 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
    color: var(--text-primary);
}

.risk-chart-modern {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.risk-bar-modern {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.75rem;
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
}

.risk-label-modern {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 120px;
}

.risk-emoji {
    font-size: 1.2rem;
}

.risk-name {
    font-weight: 600;
    font-size: 0.85rem;
}

.risk-progress-container {
    flex: 1;
    height: 8px;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
}

.risk-progress-bar {
    height: 100%;
    border-radius: 4px;
    transition: var(--transition-normal);
}

.risk-count-modern {
    min-width: 40px;
    text-align: right;
    font-weight: 700;
    font-size: 1rem;
}

/* Sections */
.vulnerability-section,
.file-analysis-section,
.recommendations-section,
.technical-appendix {
    padding: 3rem 2rem;
    max-width: 1200px;
    margin: 0 auto;
    border-bottom: 1px solid var(--border-primary);
}

.section-header {
    margin-bottom: 2rem;
}

.section-header h2 {
    font-size: 2rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.section-subtitle {
    font-size: 1rem;
    color: var(--text-secondary);
}

/* Vulnerability Groups */
.vuln-group {
    margin-bottom: 2rem;
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    overflow: hidden;
    border: 1px solid var(--border-primary);
}

.vuln-group-header {
    padding: 1.5rem;
    background: var(--bg-tertiary);
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-primary);
}

.vuln-group-header h3 {
    font-size: 1.3rem;
    font-weight: 600;
}

.vuln-count {
    background: var(--bg-secondary);
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    font-size: 0.85rem;
    font-weight: 500;
}

.vuln-cards {
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

/* Enhanced Vulnerability Cards */
.vuln-card-modern {
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
    border: 1px solid var(--border-primary);
    overflow: hidden;
    transition: var(--transition-normal);
}

.vuln-card-modern:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
    border-color: var(--border-secondary);
}

.vuln-card-header {
    padding: 1.5rem;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border-primary);
    display: flex;
    gap: 1rem;
    align-items: flex-start;
}

.vuln-badge-container {
    display: flex;
    gap: 0.5rem;
    align-items: center;
}

.vuln-index {
    background: var(--accent-primary);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: var(--radius-sm);
    font-weight: 600;
    font-size: 0.85rem;
}

.vuln-risk-badge {
    padding: 0.25rem 0.75rem;
    border-radius: var(--radius-sm);
    font-weight: 600;
    font-size: 0.8rem;
}

.vuln-risk-badge.risk-critical {
    background: var(--danger);
    color: white;
}

.vuln-risk-badge.risk-high {
    background: var(--warning);
    color: black;
}

.vuln-risk-badge.risk-medium {
    background: var(--info);
    color: white;
}

.vuln-title-container {
    flex: 1;
}

.vuln-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.vuln-meta {
    display: flex;
    gap: 1rem;
    color: var(--text-muted);
    font-size: 0.85rem;
}

.vuln-card-body {
    padding: 1.5rem;
}

.vuln-description {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
    line-height: 1.6;
}

/* Code Sections */
.code-section,
.fix-section {
    margin: 1.5rem 0;
    border-radius: var(--radius-md);
    overflow: hidden;
    border: 1px solid var(--border-primary);
}

.code-header,
.fix-header {
    background: var(--bg-tertiary);
    padding: 0.75rem 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-primary);
}

.code-title,
.fix-title {
    font-weight: 600;
    font-size: 0.9rem;
}

.code-location {
    font-size: 0.8rem;
    color: var(--text-muted);
}

.code-content,
.fix-content {
    background: #000;
    overflow-x: auto;
}

.code-content pre,
.fix-content pre {
    margin: 0;
    padding: 1rem;
}

.code-content code,
.fix-content code {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.85rem;
    line-height: 1.4;
    color: #e2e8f0;
}

/* AI Analysis */
.ai-analysis-modern {
    margin: 1.5rem 0;
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(16, 185, 129, 0.1));
    border-radius: var(--radius-md);
    padding: 1rem;
    border: 1px solid rgba(59, 130, 246, 0.3);
}

.ai-header {
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--accent-primary);
}

.ai-metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
}

.ai-metric {
    text-align: center;
}

.ai-metric-label {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-bottom: 0.25rem;
}

.ai-metric-value {
    font-weight: 600;
    font-size: 1rem;
}

.ai-metric-value.confidence-high { color: var(--success); }
.ai-metric-value.confidence-medium { color: var(--warning); }
.ai-metric-value.confidence-low { color: var(--danger); }

/* Citations */
.citations-modern {
    margin: 1.5rem 0;
    background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(251, 191, 36, 0.1));
    border-radius: var(--radius-md);
    padding: 1rem;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.citations-modern h5 {
    margin-bottom: 1rem;
    color: var(--warning);
    font-weight: 600;
}

.citations-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.citation-item {
    background: var(--bg-tertiary);
    padding: 1rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-primary);
}

.citation-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.5rem;
}

.citation-link {
    color: var(--accent-primary);
    text-decoration: none;
    font-weight: 500;
}

.citation-link:hover {
    text-decoration: underline;
}

.accepted-badge {
    background: var(--success);
    color: white;
    padding: 0.2rem 0.5rem;
    border-radius: var(--radius-sm);
    font-size: 0.7rem;
}

.citation-meta {
    display: flex;
    gap: 1rem;
    font-size: 0.8rem;
    color: var(--text-muted);
}

/* Details Grid */
.vuln-details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
    border: 1px solid var(--border-primary);
}

.detail-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
}

.detail-label {
    color: var(--text-muted);
    font-weight: 500;
}

.detail-value {
    color: var(--text-primary);
    font-weight: 600;
}

/* Remediation */
.remediation-modern {
    margin: 1.5rem 0;
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.1));
    border-radius: var(--radius-md);
    padding: 1rem;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.remediation-header {
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--success);
}

.remediation-content {
    color: var(--text-secondary);
    line-height: 1.6;
}

/* File Analysis */
.file-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 1.5rem;
}

.file-card {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-primary);
    overflow: hidden;
    transition: var(--transition-normal);
}

.file-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
    border-color: var(--border-secondary);
}

.file-header {
    padding: 1.5rem;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border-primary);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.file-title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.file-icon {
    font-size: 1.2rem;
}

.file-name {
    font-weight: 600;
    font-size: 1.1rem;
}

.file-stats {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.file-vuln-count {
    background: var(--accent-primary);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: var(--radius-sm);
    font-weight: 600;
    font-size: 0.85rem;
}

.risk-pills {
    display: flex;
    gap: 0.25rem;
}

.risk-pill {
    padding: 0.2rem 0.5rem;
    border-radius: var(--radius-sm);
    font-weight: 600;
    font-size: 0.7rem;
    color: white;
    min-width: 20px;
    text-align: center;
}

.risk-pill.risk-critical { background: var(--danger); }
.risk-pill.risk-high { background: var(--warning); }
.risk-pill.risk-medium { background: var(--info); }
.risk-pill.risk-low { background: var(--success); }

.file-vulns {
    padding: 1rem;
}

.file-vuln-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem;
    margin-bottom: 0.5rem;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    transition: var(--transition-fast);
}

.file-vuln-item:hover {
    background: var(--bg-hover);
}

.vuln-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}

.vuln-dot.risk-critical { background: var(--danger); }
.vuln-dot.risk-high { background: var(--warning); }
.vuln-dot.risk-medium { background: var(--info); }
.vuln-dot.risk-low { background: var(--success); }

.vuln-link {
    color: var(--text-primary);
    text-decoration: none;
    flex: 1;
    font-weight: 500;
}

.vuln-link:hover {
    color: var(--accent-primary);
    text-decoration: underline;
}

.vuln-category-tag {
    background: var(--bg-tertiary);
    color: var(--text-muted);
    padding: 0.2rem 0.5rem;
    border-radius: var(--radius-sm);
    font-size: 0.75rem;
    border: 1px solid var(--border-primary);
}

/* Recommendations */
.recommendations-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 1.5rem;
}

.recommendation-card {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    border: 1px solid var(--border-primary);
    transition: var(--transition-normal);
}

.recommendation-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
}

.recommendation-card.priority-1 {
    border-left: 4px solid var(--danger);
    background: linear-gradient(135deg, var(--bg-card), rgba(239, 68, 68, 0.05));
}

.recommendation-card.priority-2 {
    border-left: 4px solid var(--warning);
    background: linear-gradient(135deg, var(--bg-card), rgba(245, 158, 11, 0.05));
}

.recommendation-card.priority-3 {
    border-left: 4px solid var(--info);
    background: linear-gradient(135deg, var(--bg-card), rgba(59, 130, 246, 0.05));
}

.rec-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
}

.rec-priority {
    background: var(--accent-primary);
    color: white;
    padding: 0.5rem;
    border-radius: 50%;
    font-weight: 700;
    font-size: 1rem;
    min-width: 2.5rem;
    height: 2.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
}

.rec-title {
    font-weight: 600;
    font-size: 1.1rem;
    color: var(--text-primary);
}

.rec-content {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.rec-content > div {
    font-size: 0.9rem;
    line-height: 1.5;
}

.rec-impact { color: var(--danger); }
.rec-action { color: var(--text-secondary); }
.rec-location { color: var(--text-muted); }
.rec-confidence { color: var(--success); }
.rec-evidence { color: var(--warning); }

/* Technical Appendix */
.appendix-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.appendix-card {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    border: 1px solid var(--border-primary);
}

.appendix-card h3 {
    font-size: 1.2rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--text-primary);
}

.config-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.config-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border-primary);
}

.config-item:last-child {
    border-bottom: none;
}

.config-label {
    color: var(--text-muted);
    font-weight: 500;
}

.config-value {
    color: var(--text-primary);
    font-weight: 600;
}

.raw-data-section {
    background: var(--bg-card);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    border: 1px solid var(--border-primary);
}

.raw-data-section h3 {
    margin-bottom: 1rem;
}

.data-details {
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
    border: 1px solid var(--border-primary);
}

.data-details summary {
    padding: 1rem;
    cursor: pointer;
    font-weight: 600;
    color: var(--accent-primary);
    user-select: none;
}

.data-details summary:hover {
    background: var(--bg-hover);
}

.json-data {
    background: #000;
    color: #e2e8f0;
    padding: 1rem;
    margin: 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    line-height: 1.4;
    overflow-x: auto;
}

/* Footer */
.report-footer {
    background: var(--bg-secondary);
    border-top: 1px solid var(--border-primary);
    padding: 2rem;
}

.footer-content {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text-muted);
}

.footer-left {
    font-weight: 600;
}

.footer-right {
    font-size: 0.9rem;
}

/* Responsive Design */
@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        text-align: center;
        gap: 2rem;
    }
    
    .report-meta {
        grid-template-columns: 1fr;
    }
    
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .file-grid {
        grid-template-columns: 1fr;
    }
    
    .recommendations-grid {
        grid-template-columns: 1fr;
    }
    
    .appendix-grid {
        grid-template-columns: 1fr;
    }
    
    .footer-content {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }
}

/* Print Styles */
@media print {
    body {
        background: white;
        color: black;
    }
    
    .report-container {
        background: white;
    }
    
    .ascii-header {
        background: white;
        color: black;
    }
    
    .report-header {
        background: white;
        color: black;
    }
    
    .vuln-card-modern {
        break-inside: avoid;
        page-break-inside: avoid;
    }
}

/* Animations */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.vuln-card-modern {
    animation: fadeInUp 0.5s ease-out;
}

.metric-card {
    animation: fadeInUp 0.5s ease-out;
}

.file-card {
    animation: fadeInUp 0.5s ease-out;
}
"""
    
    def _generate_enhanced_javascript(self) -> str:
        """Generate enhanced JavaScript with modern interactions"""
        return """
// Enhanced Interactive JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeEnhancedReport();
});

function initializeEnhancedReport() {
    // Initialize all interactive features
    animateMetrics();
    setupSearch();
    setupCollapsibleSections();
    setupTooltips();
    setupScrollSpy();
    setupThemeToggle();
    
    console.log('[SECURITY] Enhanced Security Report Loaded');
}

function animateMetrics() {
    // Animate metric values on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const metric = entry.target;
                const value = metric.querySelector('.metric-value');
                if (value) {
                    animateNumber(value);
                }
            }
        });
    }, { threshold: 0.5 });
    
    document.querySelectorAll('.metric-card').forEach(card => {
        observer.observe(card);
    });
}

function animateNumber(element) {
    const finalValue = parseInt(element.textContent) || 0;
    const duration = 1000;
    const increment = finalValue / (duration / 16);
    let current = 0;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= finalValue) {
            current = finalValue;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 16);
}

function setupSearch() {
    // Create floating search bar
    const searchContainer = document.createElement('div');
    searchContainer.className = 'floating-search';
    searchContainer.innerHTML = `
        <div class="search-bar">
            <input type="text" id="vulnerability-search" placeholder="[SEARCH] Search vulnerabilities..." />
            <div class="search-results" id="search-results"></div>
        </div>
    `;
    
    document.body.appendChild(searchContainer);
    
    const searchInput = document.getElementById('vulnerability-search');
    const searchResults = document.getElementById('search-results');
    
    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase().trim();
        
        if (query.length < 2) {
            searchResults.style.display = 'none';
            return;
        }
        
        const vulnerabilities = document.querySelectorAll('.vuln-card-modern');
        const matches = [];
        
        vulnerabilities.forEach(vuln => {
            const title = vuln.querySelector('.vuln-title')?.textContent.toLowerCase() || '';
            const description = vuln.querySelector('.vuln-description')?.textContent.toLowerCase() || '';
            const file = vuln.querySelector('.vuln-file')?.textContent.toLowerCase() || '';
            
            if (title.includes(query) || description.includes(query) || file.includes(query)) {
                const titleText = vuln.querySelector('.vuln-title')?.textContent || '';
                const fileText = vuln.querySelector('.vuln-file')?.textContent || '';
                const riskLevel = vuln.querySelector('.vuln-risk-badge')?.textContent || '';
                
                matches.push({
                    id: vuln.id,
                    title: titleText,
                    file: fileText,
                    risk: riskLevel,
                    element: vuln
                });
            }
        });
        
        displaySearchResults(matches, searchResults);
    });
    
    // Close search on escape
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            searchResults.style.display = 'none';
            searchInput.value = '';
        }
    });
}

function displaySearchResults(matches, container) {
    if (matches.length === 0) {
        container.innerHTML = '<div class="no-results">No matching vulnerabilities found</div>';
    } else {
        const resultsHTML = matches.slice(0, 5).map(match => `
            <div class="search-result-item" onclick="scrollToVulnerability('${match.id}')">
                <div class="result-title">${match.title}</div>
                <div class="result-meta">${match.file} - ${match.risk}</div>
            </div>
        `).join('');
        
        container.innerHTML = resultsHTML;
    }
    
    container.style.display = 'block';
}

function scrollToVulnerability(vulnId) {
    const element = document.getElementById(vulnId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        element.classList.add('highlight');
        
        setTimeout(() => {
            element.classList.remove('highlight');
        }, 3000);
    }
    
    // Hide search results
    document.getElementById('search-results').style.display = 'none';
    document.getElementById('vulnerability-search').value = '';
}

function setupCollapsibleSections() {
    // Make vulnerability groups collapsible
    document.querySelectorAll('.vuln-group-header').forEach(header => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', function() {
            const cards = this.parentElement.querySelector('.vuln-cards');
            const isVisible = cards.style.display !== 'none';
            
            cards.style.display = isVisible ? 'none' : 'block';
            
            // Rotate icon or add visual indicator
            const indicator = this.querySelector('.collapse-indicator') || 
                           this.appendChild(document.createElement('span'));
            indicator.className = 'collapse-indicator';
            indicator.textContent = isVisible ? '▶' : '▼';
        });
    });
}

function setupTooltips() {
    // Add tooltips for technical terms
    const tooltipData = {
        'SQL Injection': 'Code injection technique exploiting database vulnerabilities',
        'XSS': 'Cross-Site Scripting attack injecting malicious scripts',
        'CSRF': 'Cross-Site Request Forgery forcing authenticated requests',
        'IDOR': 'Insecure Direct Object Reference accessing unauthorized objects',
        'CWE': 'Common Weakness Enumeration - standard vulnerability classification',
        'OWASP': 'Open Web Application Security Project guidelines'
    };
    
    Object.keys(tooltipData).forEach(term => {
        const regex = new RegExp(`\\b${term}\\b`, 'gi');
        document.body.innerHTML = document.body.innerHTML.replace(regex, 
            `<span class="tooltip" data-tooltip="${tooltipData[term]}">${term}</span>`);
    });
}

function setupScrollSpy() {
    // Add scroll spy for navigation
    const sections = document.querySelectorAll('.vulnerability-section, .file-analysis-section, .recommendations-section, .technical-appendix');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add animation or highlight current section
                entry.target.classList.add('in-view');
            }
        });
    }, { threshold: 0.1 });
    
    sections.forEach(section => {
        observer.observe(section);
    });
}

function setupThemeToggle() {
    // Add theme toggle button (future enhancement)
    const themeToggle = document.createElement('button');
    themeToggle.className = 'theme-toggle';
    themeToggle.innerHTML = '[THEME]';
    themeToggle.setAttribute('aria-label', 'Toggle theme');
    
    // Position in top right
    themeToggle.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        background: var(--bg-card);
        border: 1px solid var(--border-primary);
        border-radius: 50%;
        width: 50px;
        height: 50px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        font-size: 20px;
        transition: var(--transition-normal);
    `;
    
    document.body.appendChild(themeToggle);
    
    themeToggle.addEventListener('click', function() {
        // Theme toggle functionality (future enhancement)
        this.innerHTML = this.innerHTML === '[THEME]' ? '[LIGHT]' : '[THEME]';
    });
}

// Add enhanced CSS for interactive features
const enhancedCSS = `
.floating-search {
    position: fixed;
    top: 80px;
    right: 20px;
    z-index: 1000;
    width: 300px;
}

.search-bar {
    position: relative;
}

#vulnerability-search {
    width: 100%;
    padding: 12px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    font-size: 14px;
    transition: var(--transition-normal);
}

#vulnerability-search:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

#vulnerability-search::placeholder {
    color: var(--text-muted);
}

.search-results {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-md);
    margin-top: 4px;
    max-height: 300px;
    overflow-y: auto;
    box-shadow: var(--shadow-lg);
    display: none;
}

.search-result-item {
    padding: 12px 16px;
    cursor: pointer;
    border-bottom: 1px solid var(--border-primary);
    transition: var(--transition-fast);
}

.search-result-item:hover {
    background: var(--bg-hover);
}

.search-result-item:last-child {
    border-bottom: none;
}

.result-title {
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 4px;
}

.result-meta {
    font-size: 12px;
    color: var(--text-muted);
}

.no-results {
    padding: 16px;
    text-align: center;
    color: var(--text-muted);
    font-style: italic;
}

.highlight {
    animation: highlightPulse 3s ease-out;
}

@keyframes highlightPulse {
    0% { background-color: rgba(59, 130, 246, 0.3); transform: scale(1.02); }
    50% { background-color: rgba(59, 130, 246, 0.1); }
    100% { background-color: transparent; transform: scale(1); }
}

.collapse-indicator {
    margin-left: auto;
    font-size: 0.8rem;
    color: var(--text-muted);
    transition: var(--transition-fast);
}

.tooltip {
    position: relative;
    cursor: help;
    border-bottom: 1px dotted var(--accent-primary);
}

.tooltip:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    white-space: nowrap;
    z-index: 1000;
    border: 1px solid var(--border-primary);
    box-shadow: var(--shadow-md);
}

.in-view {
    animation: slideInView 0.6s ease-out;
}

@keyframes slideInView {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@media (max-width: 768px) {
    .floating-search {
        position: static;
        width: 100%;
        margin: 20px;
        margin-right: 40px;
    }
    
    .theme-toggle {
        top: 10px !important;
        right: 10px !important;
        width: 40px !important;
        height: 40px !important;
        font-size: 16px !important;
    }
}
`;

// Inject enhanced CSS
const style = document.createElement('style');
style.textContent = enhancedCSS;
document.head.appendChild(style);

// Console welcome message
console.log(`
[SECURITY] Enhanced Security Report Loaded Successfully!

[INTERACTIVE] Interactive Features:
[SUCCESS] Real-time vulnerability search
[SUCCESS] Smooth scrolling navigation
[SUCCESS] Collapsible sections
[SUCCESS] Animated metrics and charts
[SUCCESS] Tooltips for technical terms
[SUCCESS] Responsive design optimizations

[SEARCH] Use the search bar (top right) to quickly find specific vulnerabilities
[RESPONSIVE] Report is fully responsive and works on all devices
[PRINT] Print-friendly styling for professional documentation

Navigate with confidence - your enhanced security insights are ready!
`);
"""