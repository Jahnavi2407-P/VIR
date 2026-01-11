"""
Background tasks for malware analysis
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Optional

from .config import settings
from .database import get_db


async def analyze_sample_task(
    sample_id: str, 
    file_path: str,
    analysis_type: str = "full"
):
    """
    Main analysis task - coordinates static and dynamic analysis
    """
    db = await get_db()
    
    try:
        # Update status to analyzing
        await db.update_status(sample_id, "analyzing")
        
        results = {
            "sample_id": sample_id,
            "analysis_started": datetime.utcnow().isoformat(),
            "static_analysis": None,
            "dynamic_analysis": None,
            "classification": None,
            "mitre_attack": [],
            "recommendations": []
        }
        
        # Import analyzers
        from static_analysis.analyzer import StaticAnalyzer
        from dynamic_analysis.analyzer import DynamicAnalyzer
        from report_generator.generator import ReportGenerator
        
        # Step 1: Static Analysis
        if analysis_type in ["full", "static"]:
            try:
                static_analyzer = StaticAnalyzer(file_path)
                results["static_analysis"] = await static_analyzer.analyze()
                
                # Save intermediate result
                await db.save_analysis_result(sample_id, "static", results["static_analysis"])
            except Exception as e:
                results["static_analysis"] = {"error": str(e)}
        
        # Step 2: Dynamic Analysis (sandbox)
        if analysis_type in ["full", "dynamic"] and settings.SANDBOX_ENABLED:
            try:
                dynamic_analyzer = DynamicAnalyzer(file_path, sample_id)
                results["dynamic_analysis"] = await dynamic_analyzer.analyze()
                
                # Save intermediate result
                await db.save_analysis_result(sample_id, "dynamic", results["dynamic_analysis"])
            except Exception as e:
                results["dynamic_analysis"] = {"error": str(e), "sandbox_disabled": not settings.SANDBOX_ENABLED}
        
        # Step 3: Classification
        results["classification"] = classify_sample(results)
        
        # Step 4: Map to MITRE ATT&CK
        results["mitre_attack"] = map_to_mitre(results)
        
        # Step 5: Generate recommendations
        results["recommendations"] = generate_recommendations(results)
        
        # Step 6: Generate report
        report_generator = ReportGenerator(results)
        report_path = await report_generator.generate(
            output_dir=settings.REPORTS_DIR,
            formats=["json", "pdf"]
        )
        
        results["analysis_completed"] = datetime.utcnow().isoformat()
        
        # Update database with final results
        await db.update_status(
            sample_id,
            "completed",
            threat_level=results["classification"]["risk_level"],
            threat_type=results["classification"]["threat_type"],
            family=results["classification"]["family"],
            confidence=results["classification"]["confidence"],
            report_path=report_path,
            completed_at=datetime.utcnow()
        )
        
        return results
        
    except Exception as e:
        # Update status with error
        await db.update_status(
            sample_id,
            "error",
            error_message=str(e)
        )
        raise


def classify_sample(results: dict) -> dict:
    """
    Classify sample based on analysis results
    """
    classification = {
        "threat_type": "Unknown",
        "family": "Unknown",
        "confidence": 0.0,
        "risk_level": "LOW",
        "indicators": []
    }
    
    indicators = []
    ransomware_score = 0.0
    
    # Check static analysis indicators
    static = results.get("static_analysis", {})
    if static and not static.get("error"):
        # Check for crypto API usage
        imports = static.get("imports", [])
        crypto_apis = ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", 
                       "CryptAcquireContext", "BCryptEncrypt"]
        
        for api in crypto_apis:
            if api in imports:
                ransomware_score += 0.15
                indicators.append(f"Uses crypto API: {api}")
        
        # Check for suspicious strings
        strings = static.get("suspicious_strings", [])
        ransom_keywords = ["encrypt", "locked", "bitcoin", "ransom", 
                         "decrypt", "payment", ".onion", "wallet"]
        
        for keyword in ransom_keywords:
            if any(keyword.lower() in s.lower() for s in strings):
                ransomware_score += 0.1
                indicators.append(f"Contains suspicious string: {keyword}")
        
        # Check YARA matches
        yara_matches = static.get("yara_matches", [])
        if any("ransomware" in m.lower() for m in yara_matches):
            ransomware_score += 0.3
            indicators.append("YARA rule match: ransomware")
    
    # Check dynamic analysis indicators
    dynamic = results.get("dynamic_analysis", {})
    if dynamic and not dynamic.get("error"):
        # File encryption behavior
        file_ops = dynamic.get("file_operations", {})
        encrypted_count = file_ops.get("files_encrypted", 0)
        
        if encrypted_count > 10:
            ransomware_score += 0.3
            indicators.append(f"Encrypted {encrypted_count} files")
        
        # Registry persistence
        registry_ops = dynamic.get("registry_operations", [])
        persistence_keys = ["Run", "RunOnce", "Startup"]
        
        for op in registry_ops:
            if any(key in str(op) for key in persistence_keys):
                ransomware_score += 0.1
                indicators.append("Registry persistence detected")
                break
        
        # Shadow copy deletion
        process_ops = dynamic.get("process_operations", [])
        if any("vssadmin" in str(op).lower() or "wmic" in str(op).lower() 
               for op in process_ops):
            ransomware_score += 0.2
            indicators.append("Shadow copy deletion attempted")
        
        # Network C2 communication
        network_ops = dynamic.get("network_operations", [])
        if any(op.get("type") == "http_post" for op in network_ops):
            ransomware_score += 0.1
            indicators.append("Outbound C2 communication")
    
    # Determine classification
    classification["indicators"] = indicators
    classification["confidence"] = min(ransomware_score, 1.0)
    
    if ransomware_score >= 0.7:
        classification["threat_type"] = "Ransomware"
        classification["risk_level"] = "CRITICAL"
        
        # Try to identify family
        classification["family"] = identify_ransomware_family(results)
        
    elif ransomware_score >= 0.4:
        classification["threat_type"] = "Suspicious"
        classification["risk_level"] = "HIGH"
        
    elif ransomware_score >= 0.2:
        classification["threat_type"] = "Potentially Unwanted"
        classification["risk_level"] = "MEDIUM"
        
    else:
        classification["threat_type"] = "Clean"
        classification["risk_level"] = "LOW"
    
    return classification


def identify_ransomware_family(results: dict) -> str:
    """
    Identify ransomware family based on indicators
    """
    static = results.get("static_analysis", {})
    yara_matches = static.get("yara_matches", [])
    strings = static.get("suspicious_strings", [])
    
    # Family identification rules
    families = {
        "LockBit": [".lockbit", "lockbit", "YOUR DATA IS STOLEN"],
        "REvil": [".revil", "sodinokibi", "REvil"],
        "Conti": [".conti", "CONTI_README"],
        "Ryuk": [".ryk", "RyukReadMe"],
        "WannaCry": [".WNCRY", "WannaCry", "@WanaDecryptor"],
        "Maze": [".maze", "MAZE_README"],
        "DarkSide": [".darkside", "DarkSide"],
        "BlackCat": [".alphv", "BlackCat", "ALPHV"]
    }
    
    # Check YARA matches first
    for family, indicators in families.items():
        if any(family.lower() in m.lower() for m in yara_matches):
            return family
    
    # Check strings
    all_strings = " ".join(strings).lower()
    for family, indicators in families.items():
        if any(ind.lower() in all_strings for ind in indicators):
            return family
    
    return "Unknown"


def map_to_mitre(results: dict) -> list:
    """
    Map analysis results to MITRE ATT&CK techniques
    """
    techniques = []
    
    classification = results.get("classification", {})
    static = results.get("static_analysis", {})
    dynamic = results.get("dynamic_analysis", {})
    
    # Encryption for Impact
    if classification.get("threat_type") == "Ransomware":
        techniques.append({
            "technique_id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Encrypts data to interrupt availability"
        })
    
    # Check for persistence mechanisms
    if dynamic:
        registry_ops = dynamic.get("registry_operations", [])
        if any("Run" in str(op) for op in registry_ops):
            techniques.append({
                "technique_id": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "description": "Adds entries to run keys for persistence"
            })
    
    # Check for defense evasion
    if dynamic:
        process_ops = dynamic.get("process_operations", [])
        
        # Shadow copy deletion
        if any("vssadmin" in str(op).lower() for op in process_ops):
            techniques.append({
                "technique_id": "T1490",
                "name": "Inhibit System Recovery",
                "tactic": "Impact",
                "description": "Deletes shadow copies to prevent recovery"
            })
        
        # Process injection
        if any("inject" in str(op).lower() for op in process_ops):
            techniques.append({
                "technique_id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion",
                "description": "Injects code into other processes"
            })
    
    # Check for C2 communication
    if dynamic:
        network_ops = dynamic.get("network_operations", [])
        if network_ops:
            techniques.append({
                "technique_id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Uses HTTP/HTTPS for C2 communication"
            })
    
    # Check for credential access
    if static:
        imports = static.get("imports", [])
        if any(api in imports for api in ["CredRead", "LsaRetrievePrivateData"]):
            techniques.append({
                "technique_id": "T1555",
                "name": "Credentials from Password Stores",
                "tactic": "Credential Access",
                "description": "Attempts to access stored credentials"
            })
    
    return techniques


def generate_recommendations(results: dict) -> list:
    """
    Generate security recommendations based on analysis
    """
    recommendations = []
    
    classification = results.get("classification", {})
    risk_level = classification.get("risk_level", "LOW")
    threat_type = classification.get("threat_type", "Unknown")
    
    if risk_level == "CRITICAL":
        recommendations.extend([
            "🚨 IMMEDIATE: Isolate affected systems from network",
            "🚨 IMMEDIATE: Preserve system state for forensic analysis",
            "📞 Contact your incident response team immediately",
            "🔍 Check for lateral movement to other systems",
            "💾 Verify backup integrity before attempting restoration",
            "📝 Document all affected systems and indicators"
        ])
    
    elif risk_level == "HIGH":
        recommendations.extend([
            "⚠️ Quarantine the file immediately",
            "🔍 Scan all systems for similar indicators",
            "📊 Review recent network traffic for anomalies",
            "🔄 Update antivirus signatures"
        ])
    
    elif risk_level == "MEDIUM":
        recommendations.extend([
            "📋 Add file hash to blocklist",
            "🔍 Monitor for similar file patterns",
            "📊 Review system logs for related activity"
        ])
    
    # Threat-specific recommendations
    if threat_type == "Ransomware":
        recommendations.extend([
            "💡 Do NOT pay the ransom - it encourages more attacks",
            "🔐 Rotate all credentials that may have been exposed",
            "📧 Report incident to relevant authorities (FBI IC3, CISA)",
            "🛡️ Implement network segmentation to prevent spread"
        ])
    
    return recommendations


# Synchronous wrapper for non-async contexts
def run_analysis_sync(sample_id: str, file_path: str, analysis_type: str = "full"):
    """Synchronous wrapper for analysis task"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            analyze_sample_task(sample_id, file_path, analysis_type)
        )
    finally:
        loop.close()
