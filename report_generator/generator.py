"""
Report Generator for Ransomware Behavior Analyzer
Generates professional threat analysis reports
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ReportSection:
    """Represents a report section"""
    title: str
    content: Any
    severity: str = "info"


class ReportGenerator:
    """
    Generates analysis reports in multiple formats
    """
    
    def __init__(self, analysis_results: Dict[str, Any]):
        self.results = analysis_results
        self.report_data = {}
    
    async def generate(
        self,
        output_dir: str,
        formats: List[str] = None
    ) -> str:
        """
        Generate report in specified formats
        Returns path to primary report file
        """
        formats = formats or ["json"]
        sample_id = self.results.get("sample_id", "unknown")
        
        # Build report data
        self.report_data = self._build_report()
        
        # Generate each format
        primary_path = None
        
        for fmt in formats:
            if fmt == "json":
                path = os.path.join(output_dir, f"{sample_id}.json")
                self._generate_json(path)
                primary_path = primary_path or path
                
            elif fmt == "pdf":
                path = os.path.join(output_dir, f"{sample_id}.pdf")
                self._generate_pdf(path)
                
            elif fmt == "html":
                path = os.path.join(output_dir, f"{sample_id}.html")
                self._generate_html(path)
                
            elif fmt == "markdown":
                path = os.path.join(output_dir, f"{sample_id}.md")
                self._generate_markdown(path)
        
        return primary_path
    
    def _build_report(self) -> Dict[str, Any]:
        """Build structured report data"""
        classification = self.results.get("classification", {})
        static = self.results.get("static_analysis", {})
        dynamic = self.results.get("dynamic_analysis", {})
        
        report = {
            "metadata": {
                "report_id": self.results.get("sample_id"),
                "generated_at": datetime.utcnow().isoformat(),
                "analyzer_version": "1.0.0",
                "analysis_duration": self._calculate_duration()
            },
            
            "executive_summary": {
                "threat_type": classification.get("threat_type", "Unknown"),
                "family": classification.get("family", "Unknown"),
                "confidence": classification.get("confidence", 0),
                "risk_level": classification.get("risk_level", "UNKNOWN"),
                "verdict": self._get_verdict(classification),
                "key_findings": self._extract_key_findings()
            },
            
            "file_information": {
                "filename": static.get("file_name", ""),
                "file_type": static.get("file_info", {}).get("file_type", ""),
                "file_size": static.get("file_info", {}).get("size_human", ""),
                "hashes": static.get("hashes", {}),
                "first_seen": self.results.get("analysis_started", ""),
            },
            
            "static_analysis": {
                "pe_info": static.get("pe_info", {}),
                "imports_count": len(static.get("imports", [])),
                "suspicious_imports": static.get("suspicious_imports", []),
                "suspicious_strings": static.get("suspicious_strings", [])[:20],
                "yara_matches": static.get("yara_matches", []),
                "risk_score": static.get("risk_score", 0)
            },
            
            "dynamic_analysis": {
                "execution_summary": {
                    "total_file_ops": dynamic.get("file_operations", {}).get("total", 0),
                    "files_encrypted": dynamic.get("file_operations", {}).get("files_encrypted", 0),
                    "registry_modifications": len(dynamic.get("registry_operations", [])),
                    "processes_created": len(dynamic.get("process_operations", [])),
                    "network_connections": len(dynamic.get("network_operations", []))
                },
                "file_operations": dynamic.get("file_operations", {}),
                "registry_operations": dynamic.get("registry_operations", [])[:20],
                "process_operations": dynamic.get("process_operations", [])[:20],
                "network_operations": dynamic.get("network_operations", [])[:20],
                "behavior_summary": dynamic.get("behavior_summary", {})
            },
            
            "mitre_attack": self._format_mitre_techniques(),
            
            "indicators_of_compromise": self._extract_iocs(),
            
            "recommendations": self.results.get("recommendations", []),
            
            "technical_details": {
                "static_indicators": classification.get("indicators", []),
                "sandbox_type": dynamic.get("sandbox_type", ""),
                "analysis_errors": self._collect_errors()
            }
        }
        
        return report
    
    def _calculate_duration(self) -> str:
        """Calculate analysis duration"""
        try:
            start = datetime.fromisoformat(self.results.get("analysis_started", ""))
            end = datetime.fromisoformat(
                self.results.get("analysis_completed", datetime.utcnow().isoformat())
            )
            duration = (end - start).total_seconds()
            return f"{duration:.2f} seconds"
        except:
            return "Unknown"
    
    def _get_verdict(self, classification: Dict) -> str:
        """Generate verdict string"""
        risk_level = classification.get("risk_level", "UNKNOWN")
        threat_type = classification.get("threat_type", "Unknown")
        
        if risk_level == "CRITICAL":
            return f"⚠️ MALICIOUS - {threat_type} detected with high confidence"
        elif risk_level == "HIGH":
            return f"🔶 SUSPICIOUS - Likely {threat_type}, requires further analysis"
        elif risk_level == "MEDIUM":
            return f"🔹 POTENTIALLY UNWANTED - Some suspicious indicators found"
        else:
            return "✅ LIKELY CLEAN - No significant threats detected"
    
    def _extract_key_findings(self) -> List[str]:
        """Extract key findings from analysis"""
        findings = []
        
        classification = self.results.get("classification", {})
        static = self.results.get("static_analysis", {})
        dynamic = self.results.get("dynamic_analysis", {})
        
        # Static findings
        suspicious_imports = static.get("suspicious_imports", [])
        if any(imp.get("category") == "encryption" for imp in suspicious_imports):
            findings.append("Uses cryptographic APIs (potential encryption capability)")
        
        if static.get("yara_matches"):
            findings.append(f"Matched {len(static['yara_matches'])} YARA rules")
        
        # Dynamic findings
        file_ops = dynamic.get("file_operations", {})
        if file_ops.get("files_encrypted", 0) > 0:
            findings.append(f"Encrypted {file_ops['files_encrypted']} files during execution")
        
        behavior = dynamic.get("behavior_summary", {})
        if behavior.get("ransomware_indicators"):
            findings.append("Exhibits ransomware behavior patterns")
        
        if behavior.get("evasion_indicators"):
            findings.append("Attempts to disable system recovery")
        
        if behavior.get("persistence_indicators"):
            findings.append("Establishes persistence mechanisms")
        
        if behavior.get("network_indicators"):
            findings.append("Communicates with external servers")
        
        return findings[:10]  # Limit to top 10
    
    def _format_mitre_techniques(self) -> List[Dict]:
        """Format MITRE ATT&CK techniques"""
        techniques = self.results.get("mitre_attack", [])
        
        return [
            {
                "technique_id": t.get("technique_id", ""),
                "name": t.get("name", ""),
                "tactic": t.get("tactic", ""),
                "description": t.get("description", ""),
                "reference": f"https://attack.mitre.org/techniques/{t.get('technique_id', '')}/"
            }
            for t in techniques
        ]
    
    def _extract_iocs(self) -> Dict[str, List]:
        """Extract indicators of compromise"""
        iocs = {
            "file_hashes": [],
            "domains": [],
            "ip_addresses": [],
            "urls": [],
            "file_paths": [],
            "registry_keys": [],
            "mutexes": []
        }
        
        # File hashes
        static = self.results.get("static_analysis", {})
        hashes = static.get("hashes", {})
        if hashes.get("sha256"):
            iocs["file_hashes"].append({
                "type": "sha256",
                "value": hashes["sha256"]
            })
        if hashes.get("md5"):
            iocs["file_hashes"].append({
                "type": "md5",
                "value": hashes["md5"]
            })
        
        # Network IOCs
        dynamic = self.results.get("dynamic_analysis", {})
        for net_op in dynamic.get("network_operations", []):
            dest = net_op.get("destination", "")
            if "." in dest:
                if dest.replace(".", "").isdigit():
                    iocs["ip_addresses"].append(dest)
                else:
                    iocs["domains"].append(dest)
        
        # File paths
        for file_op in dynamic.get("file_operations", {}).get("operations", []):
            if file_op.get("operation") == "create":
                iocs["file_paths"].append(file_op.get("path", ""))
        
        # Registry keys
        for reg_op in dynamic.get("registry_operations", []):
            iocs["registry_keys"].append(reg_op.get("key", ""))
        
        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:20]
        
        return iocs
    
    def _collect_errors(self) -> List[str]:
        """Collect any analysis errors"""
        errors = []
        
        static = self.results.get("static_analysis", {})
        if static.get("error"):
            errors.append(f"Static analysis: {static['error']}")
        
        dynamic = self.results.get("dynamic_analysis", {})
        if dynamic.get("error"):
            errors.append(f"Dynamic analysis: {dynamic['error']}")
        
        return errors
    
    def _generate_json(self, path: str):
        """Generate JSON report"""
        with open(path, 'w') as f:
            json.dump(self.report_data, f, indent=2, default=str)
    
    def _generate_html(self, path: str):
        """Generate HTML report"""
        html = self._build_html_report()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _build_html_report(self) -> str:
        """Build HTML report content"""
        summary = self.report_data["executive_summary"]
        file_info = self.report_data["file_information"]
        static = self.report_data["static_analysis"]
        dynamic = self.report_data["dynamic_analysis"]
        mitre = self.report_data["mitre_attack"]
        iocs = self.report_data["indicators_of_compromise"]
        recommendations = self.report_data["recommendations"]
        
        # Risk level colors
        risk_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745"
        }
        risk_color = risk_colors.get(summary["risk_level"], "#6c757d")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Analysis Report - {file_info['filename']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .header .subtitle {{ opacity: 0.8; }}
        
        .risk-badge {{
            display: inline-block;
            padding: 10px 30px;
            border-radius: 50px;
            font-size: 1.2rem;
            font-weight: bold;
            margin-top: 20px;
            background: {risk_color};
        }}
        
        .section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #1a1a2e;
            border-bottom: 3px solid #0066cc;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card .number {{ font-size: 2.5rem; font-weight: bold; color: #0066cc; }}
        .stat-card .label {{ color: #666; }}
        
        .finding {{ 
            padding: 10px 15px; 
            margin: 5px 0; 
            background: #fff3cd; 
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .finding.critical {{ background: #f8d7da; border-color: #dc3545; }}
        .finding.high {{ background: #ffe5d0; border-color: #fd7e14; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        
        .mitre-tag {{
            display: inline-block;
            padding: 5px 10px;
            margin: 3px;
            background: #e7f1ff;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        .mitre-tag a {{ color: #0066cc; text-decoration: none; }}
        
        .ioc {{ 
            font-family: monospace; 
            background: #f4f4f4; 
            padding: 5px 10px; 
            border-radius: 4px; 
            word-break: break-all;
            margin: 3px 0;
            display: block;
        }}
        
        .recommendation {{
            padding: 15px;
            margin: 10px 0;
            background: #e8f4fd;
            border-radius: 8px;
            border-left: 4px solid #0066cc;
        }}
        
        .verdict {{
            font-size: 1.1rem;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            margin: 15px 0;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔬 Threat Analysis Report</h1>
        <p class="subtitle">Ransomware Behavior Analyzer</p>
        <div class="risk-badge">{summary['risk_level']} RISK</div>
    </div>
    
    <div class="container">
        <!-- Executive Summary -->
        <div class="section">
            <h2>📋 Executive Summary</h2>
            <div class="verdict">{summary['verdict']}</div>
            
            <div class="grid">
                <div class="stat-card">
                    <div class="number">{summary['threat_type']}</div>
                    <div class="label">Threat Type</div>
                </div>
                <div class="stat-card">
                    <div class="number">{summary['family']}</div>
                    <div class="label">Malware Family</div>
                </div>
                <div class="stat-card">
                    <div class="number">{summary['confidence']:.0%}</div>
                    <div class="label">Confidence</div>
                </div>
            </div>
            
            <h3 style="margin-top: 20px;">Key Findings</h3>
            {''.join(f'<div class="finding">{f}</div>' for f in summary['key_findings'])}
        </div>
        
        <!-- File Information -->
        <div class="section">
            <h2>📁 File Information</h2>
            <table>
                <tr><th>Filename</th><td>{file_info['filename']}</td></tr>
                <tr><th>File Type</th><td>{file_info['file_type']}</td></tr>
                <tr><th>File Size</th><td>{file_info['file_size']}</td></tr>
                <tr><th>SHA256</th><td class="ioc">{file_info['hashes'].get('sha256', 'N/A')}</td></tr>
                <tr><th>MD5</th><td class="ioc">{file_info['hashes'].get('md5', 'N/A')}</td></tr>
            </table>
        </div>
        
        <!-- Dynamic Analysis Results -->
        <div class="section">
            <h2>⚡ Dynamic Analysis Results</h2>
            <div class="grid">
                <div class="stat-card">
                    <div class="number">{dynamic['execution_summary']['files_encrypted']}</div>
                    <div class="label">Files Encrypted</div>
                </div>
                <div class="stat-card">
                    <div class="number">{dynamic['execution_summary']['registry_modifications']}</div>
                    <div class="label">Registry Changes</div>
                </div>
                <div class="stat-card">
                    <div class="number">{dynamic['execution_summary']['network_connections']}</div>
                    <div class="label">Network Connections</div>
                </div>
                <div class="stat-card">
                    <div class="number">{dynamic['execution_summary']['processes_created']}</div>
                    <div class="label">Processes Created</div>
                </div>
            </div>
        </div>
        
        <!-- MITRE ATT&CK -->
        <div class="section">
            <h2>🎯 MITRE ATT&CK Mapping</h2>
            <div>
                {''.join(f'<span class="mitre-tag"><a href="{t["reference"]}" target="_blank">{t["technique_id"]}</a> - {t["name"]}</span>' for t in mitre)}
            </div>
            <table style="margin-top: 20px;">
                <tr><th>Technique</th><th>Tactic</th><th>Description</th></tr>
                {''.join(f'<tr><td><a href="{t["reference"]}">{t["technique_id"]}</a></td><td>{t["tactic"]}</td><td>{t["description"]}</td></tr>' for t in mitre)}
            </table>
        </div>
        
        <!-- IOCs -->
        <div class="section">
            <h2>🔍 Indicators of Compromise</h2>
            <div class="grid">
                <div>
                    <h4>File Hashes</h4>
                    {''.join(f'<span class="ioc">{h["type"]}: {h["value"]}</span>' for h in iocs.get("file_hashes", []))}
                </div>
                <div>
                    <h4>Network Indicators</h4>
                    {''.join(f'<span class="ioc">{ip}</span>' for ip in iocs.get("ip_addresses", []))}
                    {''.join(f'<span class="ioc">{d}</span>' for d in iocs.get("domains", []))}
                </div>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <h2>💡 Recommendations</h2>
            {''.join(f'<div class="recommendation">{r}</div>' for r in recommendations)}
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by Ransomware Behavior Analyzer v1.0</p>
        <p>Report ID: {self.report_data['metadata']['report_id']} | Generated: {self.report_data['metadata']['generated_at']}</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_pdf(self, path: str):
        """Generate PDF report"""
        try:
            # Try using weasyprint
            from weasyprint import HTML
            
            html_content = self._build_html_report()
            HTML(string=html_content).write_pdf(path)
            
        except ImportError:
            # Fallback: save as HTML with .pdf extension note
            html_path = path.replace('.pdf', '_report.html')
            self._generate_html(html_path)
            
            # Create a simple text PDF indicator
            with open(path, 'w') as f:
                f.write(f"PDF generation requires weasyprint.\n")
                f.write(f"HTML report saved to: {html_path}\n")
                f.write(f"Install weasyprint: pip install weasyprint\n")
    
    def _generate_markdown(self, path: str):
        """Generate Markdown report"""
        summary = self.report_data["executive_summary"]
        file_info = self.report_data["file_information"]
        mitre = self.report_data["mitre_attack"]
        iocs = self.report_data["indicators_of_compromise"]
        recommendations = self.report_data["recommendations"]
        
        md = f"""# 🔬 Threat Analysis Report

**Generated:** {self.report_data['metadata']['generated_at']}  
**Report ID:** {self.report_data['metadata']['report_id']}

---

## 📋 Executive Summary

| Field | Value |
|-------|-------|
| **Threat Type** | {summary['threat_type']} |
| **Family** | {summary['family']} |
| **Confidence** | {summary['confidence']:.0%} |
| **Risk Level** | **{summary['risk_level']}** |

### Verdict
{summary['verdict']}

### Key Findings
{''.join(f"- {f}" + chr(10) for f in summary['key_findings'])}

---

## 📁 File Information

| Property | Value |
|----------|-------|
| **Filename** | `{file_info['filename']}` |
| **File Type** | {file_info['file_type']} |
| **File Size** | {file_info['file_size']} |
| **SHA256** | `{file_info['hashes'].get('sha256', 'N/A')}` |
| **MD5** | `{file_info['hashes'].get('md5', 'N/A')}` |

---

## 🎯 MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|-----------|------|--------|
{''.join(f"| [{t['technique_id']}]({t['reference']}) | {t['name']} | {t['tactic']} |" + chr(10) for t in mitre)}

---

## 🔍 Indicators of Compromise

### File Hashes
{''.join(f"- `{h['type']}`: `{h['value']}`" + chr(10) for h in iocs.get('file_hashes', []))}

### Network Indicators
**IP Addresses:**
{''.join(f"- `{ip}`" + chr(10) for ip in iocs.get('ip_addresses', [])) or '- None detected'}

**Domains:**
{''.join(f"- `{d}`" + chr(10) for d in iocs.get('domains', [])) or '- None detected'}

---

## 💡 Recommendations

{''.join(f"{i+1}. {r}" + chr(10) for i, r in enumerate(recommendations))}

---

*Report generated by Ransomware Behavior Analyzer v1.0*
"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(md)


# Standalone function
async def generate_report(
    analysis_results: Dict[str, Any],
    output_dir: str,
    formats: List[str] = None
) -> str:
    """Generate analysis report"""
    generator = ReportGenerator(analysis_results)
    return await generator.generate(output_dir, formats)


if __name__ == "__main__":
    import asyncio
    
    # Test with sample data
    sample_results = {
        "sample_id": "test-123",
        "analysis_started": datetime.utcnow().isoformat(),
        "analysis_completed": datetime.utcnow().isoformat(),
        "classification": {
            "threat_type": "Ransomware",
            "family": "LockBit",
            "confidence": 0.87,
            "risk_level": "CRITICAL",
            "indicators": ["encryption", "persistence"]
        },
        "static_analysis": {
            "file_name": "malware.exe",
            "file_info": {"file_type": "PE32 executable", "size_human": "256 KB"},
            "hashes": {
                "sha256": "abc123def456...",
                "md5": "abc123..."
            },
            "suspicious_imports": [
                {"function": "CryptEncrypt", "category": "encryption"}
            ],
            "yara_matches": [{"rule": "ransomware_lockbit"}],
            "risk_score": 85
        },
        "dynamic_analysis": {
            "file_operations": {"total": 1500, "files_encrypted": 1245},
            "registry_operations": [{"key": "HKCU\\...\\Run", "operation": "set"}],
            "process_operations": [{"process_name": "vssadmin.exe", "command_line": "delete shadows"}],
            "network_operations": [{"destination": "185.100.85.100", "port": 443}],
            "behavior_summary": {"ransomware_indicators": [{"indicator": "mass_encryption"}]}
        },
        "mitre_attack": [
            {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Encrypts data"}
        ],
        "recommendations": ["Isolate system", "Check backups"]
    }
    
    async def test():
        generator = ReportGenerator(sample_results)
        
        os.makedirs("./test_reports", exist_ok=True)
        
        path = await generator.generate(
            "./test_reports",
            formats=["json", "html", "markdown"]
        )
        
        print(f"Report generated: {path}")
    
    asyncio.run(test())
