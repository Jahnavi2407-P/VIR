"""
MITRE ATT&CK Framework mapping for malware analysis
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique"""
    technique_id: str
    name: str
    tactic: str
    description: str
    detection: str = ""
    platforms: List[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "detection": self.detection,
            "reference": f"https://attack.mitre.org/techniques/{self.technique_id}/"
        }


# MITRE ATT&CK Techniques Database (Ransomware-focused)
MITRE_TECHNIQUES = {
    # Impact
    "T1486": MITRETechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data on target systems to interrupt availability. Ransomware encrypts files and demands payment for decryption.",
        detection="Monitor file system for mass file modifications and extension changes"
    ),
    "T1490": MITRETechnique(
        technique_id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        description="Adversaries may delete or remove built-in operating system recovery data to prevent victims from recovering.",
        detection="Monitor for vssadmin, wmic shadowcopy, bcdedit commands"
    ),
    "T1489": MITRETechnique(
        technique_id="T1489",
        name="Service Stop",
        tactic="Impact",
        description="Adversaries may stop services to render system unusable or to stop security services.",
        detection="Monitor for net stop, sc stop commands targeting security services"
    ),
    "T1491": MITRETechnique(
        technique_id="T1491",
        name="Defacement",
        tactic="Impact",
        description="Adversaries may modify visual content to intimidate or spread messages.",
        detection="Monitor for wallpaper changes, ransom note creation"
    ),
    
    # Persistence
    "T1547.001": MITRETechnique(
        technique_id="T1547.001",
        name="Registry Run Keys / Startup Folder",
        tactic="Persistence",
        description="Adversaries may add programs to Run keys or startup folder for persistence.",
        detection="Monitor registry Run keys and startup folder modifications"
    ),
    "T1053": MITRETechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence",
        description="Adversaries may use task scheduling for persistent execution.",
        detection="Monitor scheduled task creation via schtasks or Task Scheduler"
    ),
    "T1543.003": MITRETechnique(
        technique_id="T1543.003",
        name="Windows Service",
        tactic="Persistence",
        description="Adversaries may create or modify Windows services for persistence.",
        detection="Monitor service creation and modification"
    ),
    
    # Defense Evasion
    "T1562.001": MITRETechnique(
        technique_id="T1562.001",
        name="Disable or Modify Tools",
        tactic="Defense Evasion",
        description="Adversaries may disable security tools to evade detection.",
        detection="Monitor for security software process termination"
    ),
    "T1070": MITRETechnique(
        technique_id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Adversaries may delete logs and other evidence.",
        detection="Monitor for log deletion commands"
    ),
    "T1055": MITRETechnique(
        technique_id="T1055",
        name="Process Injection",
        tactic="Defense Evasion",
        description="Adversaries may inject code into processes to evade detection.",
        detection="Monitor for suspicious API calls like WriteProcessMemory"
    ),
    "T1027": MITRETechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        description="Adversaries may obfuscate files to evade analysis.",
        detection="Monitor for packed executables and encoded scripts"
    ),
    
    # Discovery
    "T1083": MITRETechnique(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        description="Adversaries may enumerate files to find valuable data to encrypt.",
        detection="Monitor for directory traversal patterns"
    ),
    "T1082": MITRETechnique(
        technique_id="T1082",
        name="System Information Discovery",
        tactic="Discovery",
        description="Adversaries may gather system information before attack.",
        detection="Monitor for systeminfo, hostname commands"
    ),
    "T1016": MITRETechnique(
        technique_id="T1016",
        name="System Network Configuration Discovery",
        tactic="Discovery",
        description="Adversaries may look for network configuration to identify targets.",
        detection="Monitor for ipconfig, netstat commands"
    ),
    
    # Command and Control
    "T1071": MITRETechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries may communicate via application layer protocols.",
        detection="Monitor HTTP/HTTPS traffic for suspicious patterns"
    ),
    "T1573": MITRETechnique(
        technique_id="T1573",
        name="Encrypted Channel",
        tactic="Command and Control",
        description="Adversaries may encrypt C2 communications.",
        detection="Monitor for encrypted traffic to unknown destinations"
    ),
    "T1105": MITRETechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversaries may transfer tools from external systems.",
        detection="Monitor for file downloads from suspicious sources"
    ),
    
    # Execution
    "T1059.001": MITRETechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="Adversaries may use PowerShell for execution.",
        detection="Monitor for suspicious PowerShell commands and scripts"
    ),
    "T1059.003": MITRETechnique(
        technique_id="T1059.003",
        name="Windows Command Shell",
        tactic="Execution",
        description="Adversaries may use cmd.exe for execution.",
        detection="Monitor for suspicious command line arguments"
    ),
    "T1204": MITRETechnique(
        technique_id="T1204",
        name="User Execution",
        tactic="Execution",
        description="Adversaries may rely on user execution.",
        detection="Monitor for execution from email attachments or downloads"
    ),
    
    # Credential Access
    "T1555": MITRETechnique(
        technique_id="T1555",
        name="Credentials from Password Stores",
        tactic="Credential Access",
        description="Adversaries may search for credential storage locations.",
        detection="Monitor access to credential stores"
    ),
    "T1003": MITRETechnique(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        description="Adversaries may dump credentials from OS.",
        detection="Monitor for LSASS access and credential dumping tools"
    ),
    
    # Lateral Movement
    "T1021": MITRETechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may use remote services to move laterally.",
        detection="Monitor for RDP, SMB lateral movement"
    ),
    "T1570": MITRETechnique(
        technique_id="T1570",
        name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        description="Adversaries may transfer tools between systems.",
        detection="Monitor for file transfers between internal systems"
    ),
    
    # Exfiltration
    "T1041": MITRETechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries may exfiltrate data over the C2 channel.",
        detection="Monitor for large data transfers to C2"
    ),
    "T1567": MITRETechnique(
        technique_id="T1567",
        name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        description="Adversaries may use web services for exfiltration.",
        detection="Monitor uploads to cloud storage services"
    )
}


class MITREMapper:
    """
    Maps malware behaviors to MITRE ATT&CK framework
    """
    
    # Behavior to technique mapping rules
    BEHAVIOR_MAPPINGS = {
        # File operations
        "mass_file_encryption": ["T1486"],
        "file_extension_change": ["T1486"],
        "ransom_note_creation": ["T1486", "T1491"],
        
        # Recovery inhibition
        "shadow_copy_deletion": ["T1490"],
        "recovery_disable": ["T1490"],
        "backup_deletion": ["T1490"],
        
        # Persistence
        "registry_run_key": ["T1547.001"],
        "scheduled_task": ["T1053"],
        "service_creation": ["T1543.003"],
        "startup_folder": ["T1547.001"],
        
        # Defense evasion
        "security_disable": ["T1562.001"],
        "log_deletion": ["T1070"],
        "process_injection": ["T1055"],
        "packing": ["T1027"],
        
        # Network
        "c2_communication": ["T1071"],
        "encrypted_traffic": ["T1573"],
        "file_download": ["T1105"],
        "data_exfiltration": ["T1041"],
        
        # Execution
        "powershell_execution": ["T1059.001"],
        "cmd_execution": ["T1059.003"],
        "wscript_execution": ["T1059.005"],
        
        # Discovery
        "file_enumeration": ["T1083"],
        "system_info_query": ["T1082"],
        "network_discovery": ["T1016"],
        
        # Credential access
        "credential_access": ["T1555"],
        "lsass_access": ["T1003"]
    }
    
    def __init__(self):
        self.techniques = MITRE_TECHNIQUES
        self.mapped_techniques: List[MITRETechnique] = []
    
    def map_behaviors(self, behaviors: List[str]) -> List[Dict]:
        """Map list of behaviors to MITRE techniques"""
        technique_ids = set()
        
        for behavior in behaviors:
            behavior_lower = behavior.lower().replace(" ", "_")
            
            # Direct mapping
            if behavior_lower in self.BEHAVIOR_MAPPINGS:
                technique_ids.update(self.BEHAVIOR_MAPPINGS[behavior_lower])
            else:
                # Fuzzy matching
                for key, techniques in self.BEHAVIOR_MAPPINGS.items():
                    if key in behavior_lower or behavior_lower in key:
                        technique_ids.update(techniques)
        
        # Get technique details
        self.mapped_techniques = [
            self.techniques[tid]
            for tid in technique_ids
            if tid in self.techniques
        ]
        
        return [t.to_dict() for t in self.mapped_techniques]
    
    def map_from_analysis(self, analysis_results: Dict) -> List[Dict]:
        """Map analysis results to MITRE techniques"""
        behaviors = []
        
        # Extract behaviors from static analysis
        static = analysis_results.get("static_analysis", {})
        
        # Check imports
        imports = static.get("suspicious_imports", [])
        for imp in imports:
            category = imp.get("category", "")
            if category == "encryption":
                behaviors.append("mass_file_encryption")
            elif category == "process_injection":
                behaviors.append("process_injection")
            elif category == "registry":
                behaviors.append("registry_run_key")
            elif category == "credential_access":
                behaviors.append("credential_access")
        
        # Check for packing
        if static.get("pe_info", {}).get("packed"):
            behaviors.append("packing")
        
        # Extract behaviors from dynamic analysis
        dynamic = analysis_results.get("dynamic_analysis", {})
        
        # File operations
        file_ops = dynamic.get("file_operations", {})
        if file_ops.get("files_encrypted", 0) > 0:
            behaviors.append("mass_file_encryption")
        
        # Check for ransom notes
        for op in file_ops.get("operations", []):
            if any(kw in op.get("path", "").lower() 
                   for kw in ["readme", "restore", "decrypt"]):
                behaviors.append("ransom_note_creation")
                break
        
        # Registry operations
        for reg_op in dynamic.get("registry_operations", []):
            key = reg_op.get("key", "").lower()
            if "run" in key:
                behaviors.append("registry_run_key")
            if "services" in key:
                behaviors.append("service_creation")
        
        # Process operations
        for proc_op in dynamic.get("process_operations", []):
            cmd = (proc_op.get("command_line") or "").lower()
            name = proc_op.get("process_name", "").lower()
            
            if "vssadmin" in cmd or "shadowcopy" in cmd:
                behaviors.append("shadow_copy_deletion")
            if "bcdedit" in cmd and "recovery" in cmd:
                behaviors.append("recovery_disable")
            if "powershell" in name:
                behaviors.append("powershell_execution")
            if "cmd" in name:
                behaviors.append("cmd_execution")
        
        # Network operations
        for net_op in dynamic.get("network_operations", []):
            behaviors.append("c2_communication")
            
            if net_op.get("data", {}).get("method") == "POST":
                behaviors.append("data_exfiltration")
        
        # Deduplicate and map
        behaviors = list(set(behaviors))
        return self.map_behaviors(behaviors)
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """Get all techniques for a tactic"""
        return [
            t for t in self.techniques.values()
            if t.tactic.lower() == tactic.lower()
        ]
    
    def get_all_tactics(self) -> List[str]:
        """Get list of all tactics"""
        return list(set(t.tactic for t in self.techniques.values()))


def map_to_mitre(analysis_results: Dict) -> List[Dict]:
    """Convenience function to map analysis to MITRE"""
    mapper = MITREMapper()
    return mapper.map_from_analysis(analysis_results)


if __name__ == "__main__":
    # Test MITRE mapping
    mapper = MITREMapper()
    
    behaviors = [
        "mass_file_encryption",
        "shadow_copy_deletion",
        "registry_run_key",
        "c2_communication"
    ]
    
    techniques = mapper.map_behaviors(behaviors)
    
    print("Mapped MITRE ATT&CK Techniques:")
    for t in techniques:
        print(f"  - {t['technique_id']}: {t['name']} ({t['tactic']})")
