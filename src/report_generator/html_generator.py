"""
HTML Report Generator - Beautiful Security Reports with CSS/JS
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import base64

from .models import SecurityReport, VulnerabilityFinding, RiskLevel, VulnerabilityCategory


class HTMLReportGenerator:
    """Generates beautiful HTML security reports"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.assets_dir = Path(__file__).parent / "assets"
        
    def generate_report(self, report: SecurityReport, output_path: Path) -> Path:
        """Generate complete HTML security report"""
        
        # Generate the complete HTML content
        html_content = self._generate_html_content(report)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Security report generated: {output_path}")
        return output_path
    
    def _generate_html_content(self, report: SecurityReport) -> str:
        """Generate complete HTML content"""
        
        # Generate all sections
        css = self._generate_css()
        js = self._generate_javascript()
        ascii_art = self._generate_ascii_art()
        header = self._generate_header(report)
        executive_summary = self._generate_executive_summary(report)
        vulnerability_details = self._generate_vulnerability_details(report)
        file_analysis = self._generate_file_analysis(report)
        recommendations = self._generate_recommendations(report)
        appendix = self._generate_appendix(report)
        
        # Combine into complete HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {report.title}</title>
    <style>{css}</style>
</head>
<body>
    <div class="report-container">
        {ascii_art}
        {header}
        {executive_summary}
        {vulnerability_details}
        {file_analysis}
        {recommendations}
        {appendix}
    </div>
    
    <script>{js}</script>
</body>
</html>"""
        
        return html
    
    def _generate_ascii_art(self) -> str:
        """Generate ASCII art header"""
        return """
<div class="ascii-art">
<pre>
 ██████╗ ██████╗ ██████╗ ███████╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗      ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
██║     ██║   ██║██║  ██║██╔══╝      ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
╚██████╗╚██████╔╝██████╔╝███████╗    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
                                                                                                    
                    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗                           
                    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝                           
                    ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║                              
                    ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║                              
                    ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║                              
                    ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                              
</pre>
</div>"""
    
    def _generate_header(self, report: SecurityReport) -> str:
        """Generate report header"""
        return f"""
<div class="report-header">
    <div class="header-content">
        <h1>🛡️ Security Analysis Report</h1>
        <div class="report-meta">
            <div class="meta-item">
                <strong>Report ID:</strong> {report.report_id}
            </div>
            <div class="meta-item">
                <strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
            <div class="meta-item">
                <strong>Target:</strong> {report.target_path}
            </div>
            <div class="meta-item">
                <strong>Scan Duration:</strong> {report.scan_duration:.2f} seconds
            </div>
        </div>
    </div>
    
    <div class="risk-gauge">
        <div class="gauge-container">
            <div class="gauge-arc" data-score="{report.get_risk_score():.1f}">
                <div class="gauge-needle"></div>
            </div>
            <div class="gauge-center">
                <div class="gauge-score">{report.get_risk_score():.0f}</div>
                <div class="gauge-label">Risk Score</div>
            </div>
        </div>
    </div>
</div>"""
    
    def _generate_executive_summary(self, report: SecurityReport) -> str:
        """Generate executive summary section"""
        critical_high = report.get_critical_and_high_count()
        total_vulns = report.get_total_vulnerabilities()
        
        # Risk assessment
        if critical_high > 10:
            risk_assessment = "🔥 **CRITICAL ATTENTION REQUIRED** - Multiple high-severity vulnerabilities detected"
            risk_class = "critical"
        elif critical_high > 5:
            risk_assessment = "🔴 **HIGH RISK** - Significant security vulnerabilities found"  
            risk_class = "high"
        elif critical_high > 0:
            risk_assessment = "🟡 **MODERATE RISK** - Some security issues require attention"
            risk_class = "medium"
        else:
            risk_assessment = "🟢 **LOW RISK** - Minimal security concerns identified"
            risk_class = "low"
        
        # Top languages
        top_languages = sorted(report.languages_detected, key=lambda x: x.vulnerability_count, reverse=True)[:3]
        language_list = ", ".join([f"{lang.language} ({lang.vulnerability_count} issues)" for lang in top_languages])
        
        # Top frameworks  
        framework_list = ", ".join([fw.name for fw in report.frameworks_detected])
        
        return f"""
<div class="section executive-summary">
    <h2>📊 Executive Summary</h2>
    
    <div class="summary-grid">
        <div class="summary-card risk-{risk_class}">
            <h3>Risk Assessment</h3>
            <p>{risk_assessment}</p>
        </div>
        
        <div class="summary-card">
            <h3>📈 Key Metrics</h3>
            <ul>
                <li><strong>Total Files Scanned:</strong> {report.total_files_scanned}</li>
                <li><strong>Lines of Code:</strong> {report.total_lines_scanned:,}</li>
                <li><strong>Vulnerabilities Found:</strong> {total_vulns}</li>
                <li><strong>Critical/High Priority:</strong> {critical_high}</li>
                <li><strong>Stack Overflow Citations:</strong> {report.stack_overflow_citations_count}</li>
            </ul>
        </div>
        
        <div class="summary-card">
            <h3>🔍 Analysis Details</h3>
            <ul>
                <li><strong>Languages:</strong> {language_list}</li>
                <li><strong>Frameworks:</strong> {framework_list or 'None detected'}</li>
                <li><strong>AI Analysis:</strong> {'✅ Enabled' if report.ai_analysis_enabled else '❌ Disabled'}</li>
                <li><strong>Phases Completed:</strong> {len(report.phases_completed)}/4</li>
            </ul>
        </div>
    </div>
    
    <div class="vulnerability-breakdown">
        <h3>🎯 Vulnerability Breakdown by Risk Level</h3>
        <div class="breakdown-chart">
            {self._generate_risk_breakdown_chart(report)}
        </div>
    </div>
</div>"""
    
    def _generate_risk_breakdown_chart(self, report: SecurityReport) -> str:
        """Generate risk breakdown chart"""
        total = report.get_total_vulnerabilities()
        if total == 0:
            return "<p>No vulnerabilities detected.</p>"
        
        chart_html = '<div class="risk-chart">'
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            count = report.vulnerability_counts.get(risk_level, 0)
            percentage = (count / total * 100) if total > 0 else 0
            
            if count > 0:
                chart_html += f"""
                <div class="risk-bar risk-{risk_level.value}">
                    <div class="risk-label">{risk_level.value.upper()}</div>
                    <div class="risk-bar-fill" style="width: {percentage}%"></div>
                    <div class="risk-count">{count}</div>
                </div>"""
        
        chart_html += '</div>'
        return chart_html
    
    def _generate_vulnerability_details(self, report: SecurityReport) -> str:
        """Generate detailed vulnerability listings"""
        
        # Group vulnerabilities by priority
        critical_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.CRITICAL]
        high_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.HIGH]
        medium_vulns = [v for v in report.vulnerabilities if v.risk_level == RiskLevel.MEDIUM]
        
        html = """
<div class="section vulnerability-details">
    <h2>🔍 Detailed Vulnerability Analysis</h2>
    <p>Vulnerabilities are listed in order of priority, with mandatory Stack Overflow citations for remediation.</p>
"""
        
        # Critical vulnerabilities first
        if critical_vulns:
            html += self._generate_vulnerability_section("🔥 Critical Priority Vulnerabilities", critical_vulns, "critical")
        
        if high_vulns:
            html += self._generate_vulnerability_section("🔴 High Priority Vulnerabilities", high_vulns, "high")
        
        if medium_vulns:
            html += self._generate_vulnerability_section("🟡 Medium Priority Vulnerabilities", medium_vulns, "medium")
        
        html += "</div>"
        return html
    
    def _generate_vulnerability_section(self, title: str, vulnerabilities: List[VulnerabilityFinding], risk_class: str) -> str:
        """Generate a section for vulnerabilities of a specific risk level"""
        
        html = f"""
<div class="vulnerability-section risk-{risk_class}">
    <h3>{title}</h3>
    <div class="vulnerability-list">
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            html += self._generate_vulnerability_card(vuln, i)
        
        html += """
    </div>
</div>"""
        
        return html
    
    def _generate_vulnerability_card(self, vuln: VulnerabilityFinding, index: int) -> str:
        """Generate individual vulnerability card"""
        
        # Stack Overflow citations
        citations_html = ""
        if vuln.stack_overflow_citations:
            citations_html = "<div class='citations'><h5>📚 Stack Overflow Citations (Evidence-Based Fixes):</h5><ul>"
            for citation in vuln.stack_overflow_citations:
                accepted_badge = "✅ Accepted" if citation.accepted_answer else ""
                citations_html += f"""
                <li>
                    <a href="{citation.url}" target="_blank">
                        <strong>SO#{citation.question_id}:</strong> {citation.title}
                    </a>
                    <div class="citation-meta">
                        Score: {citation.score} | Answers: {citation.answer_count} | Relevance: {citation.relevance_score:.1f}% {accepted_badge}
                    </div>
                </li>"""
            citations_html += "</ul></div>"
        else:
            citations_html = "<div class='citations warning'>⚠️ No Stack Overflow citations found for this vulnerability</div>"
        
        # Code snippet
        code_html = ""
        if vuln.vulnerable_code:
            code_html = f"""
            <div class="code-snippet">
                <h5>🚨 Vulnerable Code ({vuln.vulnerable_code.get_line_range()}):</h5>
                <pre><code class="language-{vuln.vulnerable_code.language}">{self._escape_html(vuln.vulnerable_code.content)}</code></pre>
            </div>"""
        
        # Fix example
        fix_html = ""
        if vuln.fix_code_example:
            fix_html = f"""
            <div class="fix-example">
                <h5>✅ Recommended Fix:</h5>
                <pre><code class="language-{vuln.vulnerable_code.language if vuln.vulnerable_code else 'text'}">{self._escape_html(vuln.fix_code_example)}</code></pre>
            </div>"""
        
        # AI Analysis
        ai_html = ""
        if vuln.ai_confidence > 0:
            confidence_class = "high" if vuln.ai_confidence >= 0.8 else "medium" if vuln.ai_confidence >= 0.6 else "low"
            ai_html = f"""
            <div class="ai-analysis">
                <h5>🤖 AI Analysis:</h5>
                <div class="ai-metrics">
                    <span class="confidence confidence-{confidence_class}">Confidence: {vuln.ai_confidence:.1%}</span>
                    <span class="false-positive">False Positive Risk: {vuln.false_positive_probability:.1%}</span>
                    <span class="business-impact">Business Impact: {vuln.business_impact}</span>
                </div>
            </div>"""
        
        return f"""
<div class="vulnerability-card" id="vuln-{vuln.vulnerability_id}">
    <div class="vuln-header">
        <div class="vuln-title">
            <span class="vuln-index">#{index}</span>
            <span class="risk-badge risk-{vuln.risk_level.value}">{vuln.get_risk_emoji()} {vuln.risk_level.value.upper()}</span>
            <h4>{vuln.title}</h4>
        </div>
        <div class="vuln-location">
            <span class="file-path">📁 {vuln.file_path}</span>
            <span class="line-info">📍 Line {vuln.line_start}</span>
        </div>
    </div>
    
    <div class="vuln-body">
        <div class="description">
            <p>{vuln.description}</p>
        </div>
        
        {code_html}
        
        <div class="technical-details">
            <div class="detail-grid">
                <div class="detail-item">
                    <strong>Category:</strong> {vuln.category.value.replace('_', ' ').title()}
                </div>
                <div class="detail-item">
                    <strong>CWE ID:</strong> {vuln.cwe_id or 'Not specified'}
                </div>
                <div class="detail-item">
                    <strong>OWASP:</strong> {vuln.owasp_category or 'Not mapped'}
                </div>
                <div class="detail-item">
                    <strong>Function:</strong> {vuln.function_name or 'Global scope'}
                </div>
            </div>
        </div>
        
        {ai_html}
        
        {citations_html}
        
        {fix_html}
        
        <div class="remediation">
            <h5>🔧 Remediation Steps:</h5>
            <p>{vuln.recommended_fix}</p>
        </div>
    </div>
</div>"""
    
    def _generate_file_analysis(self, report: SecurityReport) -> str:
        """Generate file-by-file analysis"""
        
        file_groups = report.get_vulnerabilities_by_file()
        
        html = """
<div class="section file-analysis">
    <h2>📁 File-by-File Analysis</h2>
    <p>Detailed breakdown of vulnerabilities found in each source file.</p>
    
    <div class="file-tree">
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
            <div class="file-card risk-{file_risk}">
                <div class="file-header">
                    <h3>📄 {file_path}</h3>
                    <div class="file-stats">
                        <span class="total-vulns">{len(vulnerabilities)} vulnerabilities</span>
                        <div class="risk-indicators">
                            {self._generate_file_risk_indicators(risk_counts)}
                        </div>
                    </div>
                </div>
                
                <div class="file-vulnerabilities">
"""
            
            for vuln in vulnerabilities:
                html += f"""
                <div class="file-vuln-item">
                    <span class="risk-dot risk-{vuln.risk_level.value}"></span>
                    <a href="#vuln-{vuln.vulnerability_id}">
                        Line {vuln.line_start}: {vuln.title}
                    </a>
                    <span class="vuln-category">{vuln.category.value.replace('_', ' ').title()}</span>
                </div>"""
            
            html += """
                </div>
            </div>"""
        
        html += """
    </div>
</div>"""
        
        return html
    
    def _generate_file_risk_indicators(self, risk_counts: Dict[RiskLevel, int]) -> str:
        """Generate risk indicators for a file"""
        indicators = []
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = risk_counts[risk_level]
            if count > 0:
                indicators.append(f'<span class="risk-indicator risk-{risk_level.value}">{count}</span>')
        
        return " ".join(indicators)
    
    def _generate_recommendations(self, report: SecurityReport) -> str:
        """Generate recommendations section"""
        
        top_vulns = report.get_top_vulnerabilities(5)
        
        html = """
<div class="section recommendations">
    <h2>💡 Priority Recommendations</h2>
    <p>Actionable steps to improve your security posture, ranked by priority and impact.</p>
    
    <div class="recommendation-list">
"""
        
        for i, vuln in enumerate(top_vulns, 1):
            html += f"""
            <div class="recommendation-card priority-{i}">
                <div class="rec-header">
                    <span class="priority-badge">Priority #{i}</span>
                    <h3>{vuln.title}</h3>
                </div>
                <div class="rec-content">
                    <p><strong>Impact:</strong> {vuln.business_impact or 'Security vulnerability that could be exploited by attackers'}</p>
                    <p><strong>Action Required:</strong> {vuln.recommended_fix}</p>
                    <p><strong>File:</strong> {vuln.file_path} (Line {vuln.line_start})</p>
                    
                    {'<p><strong>AI Confidence:</strong> ' + f'{vuln.ai_confidence:.1%}' + '</p>' if vuln.ai_confidence > 0 else ''}
                    
                    {f'<p><strong>Evidence:</strong> {len(vuln.stack_overflow_citations)} Stack Overflow citations support this recommendation</p>' if vuln.stack_overflow_citations else ''}
                </div>
            </div>"""
        
        # General security recommendations
        html += """
        <div class="general-recommendations">
            <h3>🛡️ General Security Best Practices</h3>
            <div class="best-practices-grid">
                <div class="practice-card">
                    <h4>🔐 Input Validation</h4>
                    <p>Implement comprehensive input validation and sanitization for all user inputs.</p>
                </div>
                <div class="practice-card">
                    <h4>🛠️ Parameterized Queries</h4>
                    <p>Use parameterized queries or prepared statements to prevent SQL injection.</p>
                </div>
                <div class="practice-card">
                    <h4>🚫 Output Encoding</h4>
                    <p>Properly encode all output to prevent Cross-Site Scripting (XSS) attacks.</p>
                </div>
                <div class="practice-card">
                    <h4>🔑 Authentication</h4>
                    <p>Implement strong authentication and authorization mechanisms.</p>
                </div>
            </div>
        </div>
    </div>
</div>"""
        
        return html
    
    def _generate_appendix(self, report: SecurityReport) -> str:
        """Generate appendix with technical details"""
        
        # Generate raw JSON data for technical users
        report_data = {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "total_vulnerabilities": len(report.vulnerabilities),
            "vulnerability_counts": {level.value: count for level, count in report.vulnerability_counts.items()},
            "languages": [lang.language for lang in report.languages_detected],
            "frameworks": [fw.name for fw in report.frameworks_detected]
        }
        
        return f"""
<div class="section appendix">
    <h2>📋 Technical Appendix</h2>
    
    <div class="appendix-grid">
        <div class="appendix-card">
            <h3>🔧 Analysis Configuration</h3>
            <ul>
                <li><strong>Phases Completed:</strong> {', '.join(report.phases_completed)}</li>
                <li><strong>AI Analysis:</strong> {'Enabled' if report.ai_analysis_enabled else 'Disabled'}</li>
                <li><strong>Total Scan Time:</strong> {report.scan_duration:.2f} seconds</li>
                <li><strong>Report Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
            </ul>
        </div>
        
        <div class="appendix-card">
            <h3>📊 Statistics Summary</h3>
            <ul>
                <li><strong>Files Scanned:</strong> {report.total_files_scanned}</li>
                <li><strong>Lines of Code:</strong> {report.total_lines_scanned:,}</li>
                <li><strong>Languages Detected:</strong> {len(report.languages_detected)}</li>
                <li><strong>Frameworks Detected:</strong> {len(report.frameworks_detected)}</li>
                <li><strong>Stack Overflow Citations:</strong> {report.stack_overflow_citations_count}</li>
            </ul>
        </div>
        
        <div class="appendix-card">
            <h3>⚙️ Tool Information</h3>
            <ul>
                <li><strong>Tool Name:</strong> Code Security Analyzer</li>
                <li><strong>Version:</strong> 1.0.0 (Phase 4 Complete)</li>
                <li><strong>Analysis Engine:</strong> AI-Powered with Local LLM</li>
                <li><strong>Citation System:</strong> Stack Overflow Integration</li>
            </ul>
        </div>
    </div>
    
    <div class="raw-data">
        <h3>📄 Raw Report Data (JSON)</h3>
        <details>
            <summary>Click to expand technical data</summary>
            <pre><code class="language-json">{json.dumps(report_data, indent=2)}</code></pre>
        </details>
    </div>
</div>

<div class="report-footer">
    <p>🤖 Generated by <strong>Code Security Analyzer</strong> - AI-Powered Vulnerability Detection with Stack Overflow Citations</p>
    <p>Report ID: {report.report_id} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
</div>"""
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters in text"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _generate_css(self) -> str:
        """Generate comprehensive CSS styles"""
        return """
/* Reset and Base Styles */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
}

.report-container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    box-shadow: 0 20px 60px rgba(0,0,0,0.2);
    border-radius: 15px;
    overflow: hidden;
}

/* ASCII Art Header */
.ascii-art {
    background: linear-gradient(45deg, #1a1a1a, #2d2d2d);
    color: #00ff00;
    padding: 20px;
    text-align: center;
    font-family: 'Courier New', monospace;
    font-size: 8px;
    line-height: 1;
    overflow-x: auto;
}

.ascii-art pre {
    margin: 0;
    white-space: pre;
}

/* Report Header */
.report-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 40px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.header-content h1 {
    font-size: 2.5em;
    margin-bottom: 20px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
}

.report-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-top: 20px;
}

.meta-item {
    background: rgba(255,255,255,0.1);
    padding: 10px;
    border-radius: 8px;
    backdrop-filter: blur(10px);
}

/* Risk Gauge */
.risk-gauge {
    position: relative;
}

.gauge-container {
    width: 150px;
    height: 150px;
    position: relative;
}

.gauge-arc {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    background: conic-gradient(
        from 0deg,
        #4CAF50 0deg 72deg,
        #FFC107 72deg 144deg,
        #FF9800 144deg 216deg,
        #F44336 216deg 288deg,
        #B71C1C 288deg 360deg
    );
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.gauge-center {
    width: 80%;
    height: 80%;
    background: white;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
}

.gauge-score {
    font-size: 2em;
    font-weight: bold;
    color: #333;
}

.gauge-label {
    font-size: 0.9em;
    color: #666;
}

/* Sections */
.section {
    padding: 40px;
    border-bottom: 1px solid #eee;
}

.section h2 {
    font-size: 2em;
    margin-bottom: 20px;
    color: #2c3e50;
    border-bottom: 3px solid #3498db;
    padding-bottom: 10px;
}

/* Executive Summary */
.executive-summary {
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.summary-card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    border-left: 5px solid #3498db;
}

.summary-card.risk-critical {
    border-left-color: #e74c3c;
    background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
}

.summary-card.risk-high {
    border-left-color: #f39c12;
    background: linear-gradient(135deg, #fffbf0 0%, #feebc8 100%);
}

.summary-card.risk-medium {
    border-left-color: #f1c40f;
    background: linear-gradient(135deg, #fffff0 0%, #fefcbf 100%);
}

.summary-card.risk-low {
    border-left-color: #27ae60;
    background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%);
}

.summary-card h3 {
    color: #2c3e50;
    margin-bottom: 15px;
    font-size: 1.3em;
}

.summary-card ul {
    list-style: none;
}

.summary-card li {
    padding: 5px 0;
    border-bottom: 1px solid #eee;
}

.summary-card li:last-child {
    border-bottom: none;
}

/* Risk Breakdown Chart */
.vulnerability-breakdown {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
}

.risk-chart {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.risk-bar {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 10px;
    border-radius: 8px;
    position: relative;
    overflow: hidden;
}

.risk-bar.risk-critical {
    background: linear-gradient(90deg, #e74c3c, #c0392b);
    color: white;
}

.risk-bar.risk-high {
    background: linear-gradient(90deg, #f39c12, #d68910);
    color: white;
}

.risk-bar.risk-medium {
    background: linear-gradient(90deg, #f1c40f, #d4ac0d);
    color: #333;
}

.risk-bar.risk-low {
    background: linear-gradient(90deg, #27ae60, #229954);
    color: white;
}

.risk-bar.risk-info {
    background: linear-gradient(90deg, #3498db, #2980b9);
    color: white;
}

.risk-label {
    min-width: 80px;
    font-weight: bold;
}

.risk-bar-fill {
    height: 20px;
    background: rgba(255,255,255,0.3);
    border-radius: 10px;
    flex-grow: 1;
    position: relative;
}

.risk-count {
    min-width: 40px;
    text-align: right;
    font-weight: bold;
    font-size: 1.1em;
}

/* Vulnerability Details */
.vulnerability-section {
    margin: 30px 0;
    padding: 25px;
    border-radius: 12px;
    border: 2px solid;
}

.vulnerability-section.risk-critical {
    border-color: #e74c3c;
    background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
}

.vulnerability-section.risk-high {
    border-color: #f39c12;
    background: linear-gradient(135deg, #fffbf0 0%, #feebc8 100%);
}

.vulnerability-section.risk-medium {
    border-color: #f1c40f;
    background: linear-gradient(135deg, #fffff0 0%, #fefcbf 100%);
}

.vulnerability-section h3 {
    margin-bottom: 20px;
    font-size: 1.5em;
}

/* Vulnerability Cards */
.vulnerability-card {
    background: white;
    margin: 20px 0;
    border-radius: 12px;
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    overflow: hidden;
    border-left: 5px solid;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.vulnerability-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 35px rgba(0,0,0,0.15);
}

.vulnerability-card.risk-critical {
    border-left-color: #e74c3c;
}

.vulnerability-card.risk-high {
    border-left-color: #f39c12;
}

.vulnerability-card.risk-medium {
    border-left-color: #f1c40f;
}

.vuln-header {
    background: #f8f9fa;
    padding: 20px;
    border-bottom: 1px solid #dee2e6;
}

.vuln-title {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 10px;
}

.vuln-index {
    background: #6c757d;
    color: white;
    padding: 5px 10px;
    border-radius: 50px;
    font-weight: bold;
    min-width: 40px;
    text-align: center;
}

.risk-badge {
    padding: 8px 15px;
    border-radius: 25px;
    font-weight: bold;
    font-size: 0.9em;
    text-transform: uppercase;
}

.risk-badge.risk-critical {
    background: #e74c3c;
    color: white;
}

.risk-badge.risk-high {
    background: #f39c12;
    color: white;
}

.risk-badge.risk-medium {
    background: #f1c40f;
    color: #333;
}

.risk-badge.risk-low {
    background: #27ae60;
    color: white;
}

.vuln-title h4 {
    flex-grow: 1;
    font-size: 1.3em;
    color: #2c3e50;
}

.vuln-location {
    display: flex;
    gap: 20px;
    color: #6c757d;
    font-size: 0.9em;
}

.vuln-body {
    padding: 25px;
}

.description {
    margin-bottom: 20px;
    color: #555;
    line-height: 1.8;
}

/* Code Snippets */
.code-snippet, .fix-example {
    margin: 20px 0;
    background: #f8f9fa;
    border-radius: 8px;
    overflow: hidden;
}

.code-snippet h5, .fix-example h5 {
    background: #343a40;
    color: white;
    padding: 10px 15px;
    margin: 0;
    font-size: 0.9em;
}

.fix-example h5 {
    background: #28a745;
}

.code-snippet pre, .fix-example pre {
    margin: 0;
    padding: 15px;
    overflow-x: auto;
    background: #f8f9fa;
}

.code-snippet code, .fix-example code {
    font-family: 'Fira Code', 'Courier New', monospace;
    font-size: 0.9em;
    line-height: 1.4;
}

/* Technical Details */
.technical-details {
    margin: 20px 0;
    background: #f8f9fa;
    padding: 15px;
    border-radius: 8px;
}

.detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 10px;
}

.detail-item {
    padding: 8px;
    background: white;
    border-radius: 5px;
    font-size: 0.9em;
}

/* AI Analysis */
.ai-analysis {
    margin: 20px 0;
    padding: 15px;
    background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
    border-radius: 8px;
    border-left: 4px solid #2196f3;
}

.ai-metrics {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-top: 10px;
}

.ai-metrics span {
    padding: 5px 10px;
    border-radius: 15px;
    font-size: 0.85em;
    font-weight: bold;
}

.confidence {
    background: #4caf50;
    color: white;
}

.confidence.confidence-medium {
    background: #ff9800;
}

.confidence.confidence-low {
    background: #f44336;
}

.false-positive {
    background: #f44336;
    color: white;
}

.business-impact {
    background: #9c27b0;
    color: white;
}

/* Citations */
.citations {
    margin: 20px 0;
    padding: 15px;
    background: linear-gradient(135deg, #fff3e0 0%, #ffcc80 100%);
    border-radius: 8px;
    border-left: 4px solid #ff9800;
}

.citations.warning {
    background: linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%);
    border-left-color: #ffc107;
    text-align: center;
    font-style: italic;
}

.citations h5 {
    margin-bottom: 10px;
    color: #e65100;
}

.citations ul {
    list-style: none;
}

.citations li {
    margin: 10px 0;
    padding: 10px;
    background: white;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.citations a {
    text-decoration: none;
    color: #1976d2;
    font-weight: bold;
}

.citations a:hover {
    text-decoration: underline;
}

.citation-meta {
    font-size: 0.85em;
    color: #666;
    margin-top: 5px;
}

/* Remediation */
.remediation {
    margin: 20px 0;
    padding: 15px;
    background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%);
    border-radius: 8px;
    border-left: 4px solid #4caf50;
}

.remediation h5 {
    color: #2e7d32;
    margin-bottom: 10px;
}

/* File Analysis */
.file-tree {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.file-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    overflow: hidden;
    border-left: 5px solid;
}

.file-card.risk-critical {
    border-left-color: #e74c3c;
}

.file-card.risk-high {
    border-left-color: #f39c12;
}

.file-card.risk-medium {
    border-left-color: #f1c40f;
}

.file-card.risk-low {
    border-left-color: #27ae60;
}

.file-header {
    background: #f8f9fa;
    padding: 20px;
    border-bottom: 1px solid #dee2e6;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.file-header h3 {
    color: #2c3e50;
    font-size: 1.2em;
}

.file-stats {
    display: flex;
    align-items: center;
    gap: 15px;
}

.total-vulns {
    font-weight: bold;
    color: #6c757d;
}

.risk-indicators {
    display: flex;
    gap: 5px;
}

.risk-indicator {
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: bold;
    color: white;
    min-width: 25px;
    text-align: center;
}

.risk-indicator.risk-critical {
    background: #e74c3c;
}

.risk-indicator.risk-high {
    background: #f39c12;
}

.risk-indicator.risk-medium {
    background: #f1c40f;
    color: #333;
}

.risk-indicator.risk-low {
    background: #27ae60;
}

.file-vulnerabilities {
    padding: 20px;
}

.file-vuln-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 0;
    border-bottom: 1px solid #eee;
}

.file-vuln-item:last-child {
    border-bottom: none;
}

.risk-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}

.risk-dot.risk-critical {
    background: #e74c3c;
}

.risk-dot.risk-high {
    background: #f39c12;
}

.risk-dot.risk-medium {
    background: #f1c40f;
}

.risk-dot.risk-low {
    background: #27ae60;
}

.file-vuln-item a {
    flex-grow: 1;
    text-decoration: none;
    color: #2c3e50;
    font-weight: 500;
}

.file-vuln-item a:hover {
    text-decoration: underline;
    color: #3498db;
}

.vuln-category {
    font-size: 0.8em;
    color: #6c757d;
    background: #f8f9fa;
    padding: 2px 8px;
    border-radius: 10px;
}

/* Recommendations */
.recommendation-list {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.recommendation-card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    border-left: 5px solid;
}

.recommendation-card.priority-1 {
    border-left-color: #e74c3c;
    background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
}

.recommendation-card.priority-2 {
    border-left-color: #f39c12;
    background: linear-gradient(135deg, #fffbf0 0%, #feebc8 100%);
}

.recommendation-card.priority-3 {
    border-left-color: #f1c40f;
    background: linear-gradient(135deg, #fffff0 0%, #fefcbf 100%);
}

.recommendation-card.priority-4,
.recommendation-card.priority-5 {
    border-left-color: #3498db;
    background: linear-gradient(135deg, #f0f9ff 0%, #dbeafe 100%);
}

.rec-header {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 15px;
}

.priority-badge {
    background: #6c757d;
    color: white;
    padding: 5px 12px;
    border-radius: 15px;
    font-size: 0.8em;
    font-weight: bold;
}

.rec-header h3 {
    color: #2c3e50;
    flex-grow: 1;
}

.rec-content p {
    margin: 8px 0;
    line-height: 1.6;
}

/* Best Practices */
.general-recommendations {
    margin-top: 30px;
    padding: 25px;
    background: linear-gradient(135deg, #f0f9ff 0%, #dbeafe 100%);
    border-radius: 12px;
}

.best-practices-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.practice-card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
    border-left: 4px solid #3498db;
}

.practice-card h4 {
    color: #2c3e50;
    margin-bottom: 10px;
}

/* Appendix */
.appendix {
    background: #f8f9fa;
}

.appendix-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.appendix-card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}

.appendix-card h3 {
    color: #2c3e50;
    margin-bottom: 15px;
    font-size: 1.2em;
}

.appendix-card ul {
    list-style: none;
}

.appendix-card li {
    padding: 5px 0;
    border-bottom: 1px solid #eee;
}

.appendix-card li:last-child {
    border-bottom: none;
}

.raw-data {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}

.raw-data details {
    margin-top: 15px;
}

.raw-data summary {
    cursor: pointer;
    font-weight: bold;
    color: #3498db;
    padding: 10px;
    background: #f8f9fa;
    border-radius: 5px;
}

.raw-data pre {
    background: #2d3748;
    color: #e2e8f0;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    margin-top: 10px;
}

/* Footer */
.report-footer {
    background: #2c3e50;
    color: white;
    padding: 30px;
    text-align: center;
}

.report-footer p {
    margin: 5px 0;
}

/* Responsive Design */
@media (max-width: 768px) {
    .report-header {
        flex-direction: column;
        gap: 20px;
    }
    
    .gauge-container {
        width: 120px;
        height: 120px;
    }
    
    .summary-grid {
        grid-template-columns: 1fr;
    }
    
    .vuln-title {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    
    .file-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    
    .ai-metrics {
        flex-direction: column;
    }
    
    .best-practices-grid {
        grid-template-columns: 1fr;
    }
}

/* Print Styles */
@media print {
    body {
        background: white;
    }
    
    .report-container {
        box-shadow: none;
        border-radius: 0;
    }
    
    .ascii-art {
        background: white;
        color: black;
    }
    
    .report-header {
        background: white;
        color: black;
        border-bottom: 2px solid #333;
    }
    
    .vulnerability-card {
        break-inside: avoid;
        page-break-inside: avoid;
    }
    
    .recommendation-card {
        break-inside: avoid;
        page-break-inside: avoid;
    }
}

/* Animations */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

.vulnerability-card {
    animation: fadeIn 0.5s ease-out;
}

.summary-card {
    animation: fadeIn 0.5s ease-out;
}

.recommendation-card {
    animation: fadeIn 0.5s ease-out;
}
"""
    
    def _generate_javascript(self) -> str:
        """Generate interactive JavaScript functionality"""
        return """
// Interactive functionality for the security report

document.addEventListener('DOMContentLoaded', function() {
    initializeReport();
});

function initializeReport() {
    // Initialize gauge animation
    animateGauge();
    
    // Add smooth scrolling for anchor links
    addSmoothScrolling();
    
    // Initialize collapsible sections
    initializeCollapsibles();
    
    // Add interactive charts
    animateCharts();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Add search functionality
    addSearchFunctionality();
}

function animateGauge() {
    const gauges = document.querySelectorAll('.gauge-arc');
    
    gauges.forEach(gauge => {
        const score = parseFloat(gauge.dataset.score) || 0;
        const color = getScoreColor(score);
        
        // Animate the gauge
        gauge.style.background = `conic-gradient(
            from ${score * 3.6}deg,
            ${color} 0deg,
            #e0e0e0 0deg
        )`;
        
        // Animate the score counter
        const scoreElement = gauge.querySelector('.gauge-score');
        if (scoreElement) {
            animateNumber(scoreElement, 0, score, 2000);
        }
    });
}

function getScoreColor(score) {
    if (score >= 80) return '#e74c3c';      // Critical
    if (score >= 60) return '#f39c12';      // High
    if (score >= 40) return '#f1c40f';      // Medium
    if (score >= 20) return '#27ae60';      // Low
    return '#3498db';                       // Very Low
}

function animateNumber(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current);
    }, 16);
}

function addSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

function initializeCollapsibles() {
    document.querySelectorAll('details').forEach(details => {
        details.addEventListener('toggle', function() {
            if (this.open) {
                // Animate open
                this.style.maxHeight = this.scrollHeight + 'px';
            } else {
                // Animate close
                this.style.maxHeight = '40px';
            }
        });
    });
}

function animateCharts() {
    // Animate risk breakdown bars
    const riskBars = document.querySelectorAll('.risk-bar-fill');
    
    riskBars.forEach((bar, index) => {
        const width = bar.style.width;
        bar.style.width = '0%';
        
        setTimeout(() => {
            bar.style.transition = 'width 1s ease-out';
            bar.style.width = width;
        }, index * 200);
    });
    
    // Animate vulnerability cards on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, observerOptions);
    
    document.querySelectorAll('.vulnerability-card').forEach(card => {
        observer.observe(card);
    });
}

function initializeTooltips() {
    // Add tooltips for technical terms
    const tooltipData = {
        'SQL Injection': 'A code injection technique that exploits security vulnerabilities in database layer of an application.',
        'XSS': 'Cross-Site Scripting (XSS) is a type of injection attack where malicious scripts are injected into trusted websites.',
        'CSRF': 'Cross-Site Request Forgery is an attack that forces authenticated users to submit requests to applications they trust.',
        'IDOR': 'Insecure Direct Object Reference occurs when an application provides direct access to objects based on user input.',
        'XXE': 'XML External Entity attacks exploit vulnerable XML parsers that process external entity references.',
        'SSRF': 'Server-Side Request Forgery allows attackers to make requests from the server to arbitrary destinations.'
    };
    
    Object.keys(tooltipData).forEach(term => {
        const elements = document.querySelectorAll(`*:contains("${term}")`);
        elements.forEach(element => {
            if (element.children.length === 0) {  // Only text nodes
                element.title = tooltipData[term];
                element.style.borderBottom = '1px dotted #3498db';
                element.style.cursor = 'help';
            }
        });
    });
}

function addSearchFunctionality() {
    // Create search box
    const searchBox = document.createElement('div');
    searchBox.className = 'search-box';
    searchBox.innerHTML = `
        <input type="text" id="report-search" placeholder="🔍 Search vulnerabilities..." />
        <div id="search-results" class="search-results"></div>
    `;
    
    // Add search box to header
    const header = document.querySelector('.report-header');
    if (header) {
        header.appendChild(searchBox);
    }
    
    // Search functionality
    const searchInput = document.getElementById('report-search');
    const searchResults = document.getElementById('search-results');
    
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            
            if (query.length < 2) {
                searchResults.innerHTML = '';
                searchResults.style.display = 'none';
                return;
            }
            
            const vulnerabilities = document.querySelectorAll('.vulnerability-card');
            const matches = [];
            
            vulnerabilities.forEach(vuln => {
                const title = vuln.querySelector('h4')?.textContent.toLowerCase() || '';
                const description = vuln.querySelector('.description')?.textContent.toLowerCase() || '';
                const filePath = vuln.querySelector('.file-path')?.textContent.toLowerCase() || '';
                
                if (title.includes(query) || description.includes(query) || filePath.includes(query)) {
                    const titleText = vuln.querySelector('h4')?.textContent || 'Unknown';
                    const fileText = vuln.querySelector('.file-path')?.textContent || '';
                    const riskLevel = vuln.querySelector('.risk-badge')?.textContent || '';
                    
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
    }
}

function displaySearchResults(matches, container) {
    if (matches.length === 0) {
        container.innerHTML = '<div class="no-results">No matching vulnerabilities found</div>';
    } else {
        const resultsHTML = matches.map(match => `
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
    document.getElementById('report-search').value = '';
}

// Utility function for contains selector
function createContainsSelector() {
    document.querySelectorAll = function(selector) {
        if (selector.includes(':contains(')) {
            const match = selector.match(/:contains\\("([^"]+)"\\)/);
            if (match) {
                const text = match[1];
                const elements = Array.from(document.getElementsByTagName('*'));
                return elements.filter(el => 
                    el.textContent.includes(text) && 
                    el.children.length === 0
                );
            }
        }
        return document.querySelectorAll.call(this, selector);
    };
}

// CSS for search functionality and animations
const additionalCSS = `
.search-box {
    position: relative;
    margin-top: 20px;
}

#report-search {
    width: 100%;
    padding: 12px;
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 25px;
    background: rgba(255,255,255,0.1);
    color: white;
    font-size: 16px;
    backdrop-filter: blur(10px);
}

#report-search::placeholder {
    color: rgba(255,255,255,0.7);
}

#report-search:focus {
    outline: none;
    border-color: rgba(255,255,255,0.6);
    background: rgba(255,255,255,0.2);
}

.search-results {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: white;
    border-radius: 10px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    max-height: 300px;
    overflow-y: auto;
    z-index: 1000;
    display: none;
}

.search-result-item {
    padding: 15px;
    border-bottom: 1px solid #eee;
    cursor: pointer;
    transition: background-color 0.2s ease;
}

.search-result-item:hover {
    background-color: #f8f9fa;
}

.search-result-item:last-child {
    border-bottom: none;
}

.result-title {
    font-weight: bold;
    color: #2c3e50;
    margin-bottom: 5px;
}

.result-meta {
    font-size: 0.9em;
    color: #6c757d;
}

.no-results {
    padding: 20px;
    text-align: center;
    color: #6c757d;
    font-style: italic;
}

.highlight {
    animation: highlight 3s ease-out;
}

@keyframes highlight {
    0% { background-color: #fff3cd; transform: scale(1.02); }
    100% { background-color: transparent; transform: scale(1); }
}

.animate-in {
    animation: slideInUp 0.6s ease-out;
}

@keyframes slideInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@media (max-width: 768px) {
    .search-box {
        margin-top: 15px;
    }
    
    #report-search {
        font-size: 14px;
        padding: 10px;
    }
}
`;

// Inject additional CSS
const style = document.createElement('style');
style.textContent = additionalCSS;
document.head.appendChild(style);

// Console message
console.log(`
🛡️ Security Analysis Report Loaded Successfully!

Features enabled:
✅ Interactive risk gauge
✅ Animated charts and counters  
✅ Smooth scrolling navigation
✅ Real-time vulnerability search
✅ Collapsible technical sections
✅ Responsive design for all devices

Navigate with confidence - your security insights are ready!
`);
"""