"""
Dynamic Analysis Module for Ransomware Behavior Analyzer
Monitors runtime behavior during sandbox execution
"""

import os
import json
import asyncio
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.config import settings


@dataclass
class FileOperation:
    """Represents a file system operation"""
    timestamp: str
    operation: str  # create, modify, delete, rename, encrypt
    path: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryOperation:
    """Represents a registry operation"""
    timestamp: str
    operation: str  # create, modify, delete
    key: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None


@dataclass
class ProcessOperation:
    """Represents a process operation"""
    timestamp: str
    operation: str  # create, terminate, inject
    process_name: str
    process_id: int
    parent_id: Optional[int] = None
    command_line: Optional[str] = None


@dataclass
class NetworkOperation:
    """Represents a network operation"""
    timestamp: str
    operation: str  # dns, connect, http
    destination: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    data: Optional[Dict] = None


class DynamicAnalyzer:
    """
    Dynamic analysis engine
    Monitors malware behavior during sandbox execution
    """
    
    def __init__(self, file_path: str, sample_id: str):
        self.file_path = file_path
        self.sample_id = sample_id
        self.results = {}
        
        # Behavior tracking
        self.file_operations: List[FileOperation] = []
        self.registry_operations: List[RegistryOperation] = []
        self.process_operations: List[ProcessOperation] = []
        self.network_operations: List[NetworkOperation] = []
        
        # Analysis state
        self.sandbox_enabled = settings.SANDBOX_ENABLED
        self.analysis_timeout = settings.ANALYSIS_TIMEOUT
        
    async def analyze(self) -> Dict[str, Any]:
        """
        Perform dynamic analysis
        """
        self.results = {
            "sample_id": self.sample_id,
            "file_path": self.file_path,
            "analysis_started": datetime.utcnow().isoformat(),
            "sandbox_type": settings.SANDBOX_TYPE,
            "status": "pending",
            "file_operations": {},
            "registry_operations": [],
            "process_operations": [],
            "network_operations": [],
            "behavior_summary": {},
            "indicators": []
        }
        
        try:
            if self.sandbox_enabled:
                # Real sandbox execution
                await self._run_in_sandbox()
            else:
                # Simulated analysis (for demo/testing)
                await self._simulate_analysis()
            
            # Analyze collected behaviors
            self.results["behavior_summary"] = self._analyze_behaviors()
            
            # Extract indicators
            self.results["indicators"] = self._extract_indicators()
            
            self.results["status"] = "completed"
            self.results["analysis_completed"] = datetime.utcnow().isoformat()
            
        except Exception as e:
            self.results["status"] = "error"
            self.results["error"] = str(e)
        
        return self.results
    
    async def _run_in_sandbox(self):
        """
        Execute malware in sandbox environment
        """
        from sandbox_controller.controller import SandboxController
        
        # Initialize sandbox
        sandbox = SandboxController()
        
        try:
            # Start sandbox
            await sandbox.start()
            
            # Copy malware to sandbox
            await sandbox.copy_file_to_sandbox(
                self.file_path,
                f"C:\\Samples\\{os.path.basename(self.file_path)}"
            )
            
            # Start monitoring
            await sandbox.start_monitoring()
            
            # Execute malware
            await sandbox.execute_file(
                f"C:\\Samples\\{os.path.basename(self.file_path)}",
                timeout=self.analysis_timeout
            )
            
            # Wait for execution
            await asyncio.sleep(min(self.analysis_timeout, 120))
            
            # Stop monitoring and collect data
            behavior_data = await sandbox.stop_monitoring()
            
            # Parse behavior data
            self._parse_sandbox_results(behavior_data)
            
        finally:
            # Always cleanup sandbox
            await sandbox.cleanup()
    
    async def _simulate_analysis(self):
        """
        Simulate dynamic analysis for demo/testing
        """
        # Simulate ransomware behavior
        file_ext = os.path.splitext(self.file_path)[1].lower()
        
        if file_ext in ['.exe', '.dll']:
            # Simulate typical ransomware behavior
            self._simulate_ransomware_behavior()
        else:
            # Simulate generic malware behavior
            self._simulate_generic_behavior()
        
        # Convert to results format
        self.results["file_operations"] = {
            "total": len(self.file_operations),
            "creates": len([f for f in self.file_operations if f.operation == "create"]),
            "modifies": len([f for f in self.file_operations if f.operation == "modify"]),
            "deletes": len([f for f in self.file_operations if f.operation == "delete"]),
            "encrypts": len([f for f in self.file_operations if f.operation == "encrypt"]),
            "files_encrypted": len([f for f in self.file_operations if f.operation == "encrypt"]),
            "operations": [
                {
                    "timestamp": op.timestamp,
                    "operation": op.operation,
                    "path": op.path,
                    "details": op.details
                }
                for op in self.file_operations[:100]  # Limit for report
            ]
        }
        
        self.results["registry_operations"] = [
            {
                "timestamp": op.timestamp,
                "operation": op.operation,
                "key": op.key,
                "value_name": op.value_name,
                "value_data": op.value_data
            }
            for op in self.registry_operations
        ]
        
        self.results["process_operations"] = [
            {
                "timestamp": op.timestamp,
                "operation": op.operation,
                "process_name": op.process_name,
                "process_id": op.process_id,
                "parent_id": op.parent_id,
                "command_line": op.command_line
            }
            for op in self.process_operations
        ]
        
        self.results["network_operations"] = [
            {
                "timestamp": op.timestamp,
                "operation": op.operation,
                "destination": op.destination,
                "port": op.port,
                "protocol": op.protocol,
                "data": op.data
            }
            for op in self.network_operations
        ]
    
    def _simulate_ransomware_behavior(self):
        """Simulate typical ransomware behavior patterns"""
        base_time = datetime.utcnow()
        
        # Simulate file encryption
        target_extensions = ['.docx', '.xlsx', '.pdf', '.jpg', '.txt']
        target_paths = [
            "C:\\Users\\victim\\Documents",
            "C:\\Users\\victim\\Desktop",
            "C:\\Users\\victim\\Pictures"
        ]
        
        file_count = 0
        for path in target_paths:
            for ext in target_extensions:
                for i in range(10):  # 10 files per type
                    file_count += 1
                    self.file_operations.append(FileOperation(
                        timestamp=(base_time).isoformat(),
                        operation="encrypt",
                        path=f"{path}\\document_{i}{ext}",
                        details={
                            "original_extension": ext,
                            "new_extension": f"{ext}.locked",
                            "size_changed": True
                        }
                    ))
        
        # Simulate ransom note creation
        self.file_operations.append(FileOperation(
            timestamp=(base_time).isoformat(),
            operation="create",
            path="C:\\Users\\victim\\Desktop\\README_RESTORE.txt",
            details={
                "content_type": "ransom_note",
                "size": 2048
            }
        ))
        
        # Simulate registry persistence
        self.registry_operations.append(RegistryOperation(
            timestamp=(base_time).isoformat(),
            operation="create",
            key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="SystemUpdate",
            value_data="C:\\Users\\victim\\AppData\\Local\\Temp\\malware.exe"
        ))
        
        # Simulate shadow copy deletion
        self.process_operations.append(ProcessOperation(
            timestamp=(base_time).isoformat(),
            operation="create",
            process_name="vssadmin.exe",
            process_id=1234,
            parent_id=5678,
            command_line="vssadmin delete shadows /all /quiet"
        ))
        
        self.process_operations.append(ProcessOperation(
            timestamp=(base_time).isoformat(),
            operation="create",
            process_name="wmic.exe",
            process_id=1235,
            parent_id=5678,
            command_line="wmic shadowcopy delete"
        ))
        
        # Simulate network communication
        self.network_operations.append(NetworkOperation(
            timestamp=(base_time).isoformat(),
            operation="dns",
            destination="lockbit.onion",
            protocol="tor"
        ))
        
        self.network_operations.append(NetworkOperation(
            timestamp=(base_time).isoformat(),
            operation="http",
            destination="185.100.85.100",
            port=443,
            protocol="https",
            data={
                "method": "POST",
                "path": "/key_exchange",
                "user_agent": "Mozilla/5.0"
            }
        ))
    
    def _simulate_generic_behavior(self):
        """Simulate generic malware behavior"""
        base_time = datetime.utcnow()
        
        # Basic file operations
        self.file_operations.append(FileOperation(
            timestamp=base_time.isoformat(),
            operation="create",
            path="C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe"
        ))
        
        # Network beacon
        self.network_operations.append(NetworkOperation(
            timestamp=base_time.isoformat(),
            operation="connect",
            destination="192.168.1.100",
            port=4444,
            protocol="tcp"
        ))
    
    def _parse_sandbox_results(self, behavior_data: Dict[str, Any]):
        """Parse behavior data from sandbox monitoring"""
        # Parse file operations
        for file_op in behavior_data.get("file_operations", []):
            self.file_operations.append(FileOperation(
                timestamp=file_op.get("timestamp", ""),
                operation=file_op.get("operation", ""),
                path=file_op.get("path", ""),
                details=file_op.get("details", {})
            ))
        
        # Parse registry operations
        for reg_op in behavior_data.get("registry_operations", []):
            self.registry_operations.append(RegistryOperation(
                timestamp=reg_op.get("timestamp", ""),
                operation=reg_op.get("operation", ""),
                key=reg_op.get("key", ""),
                value_name=reg_op.get("value_name"),
                value_data=reg_op.get("value_data")
            ))
        
        # Parse process operations
        for proc_op in behavior_data.get("process_operations", []):
            self.process_operations.append(ProcessOperation(
                timestamp=proc_op.get("timestamp", ""),
                operation=proc_op.get("operation", ""),
                process_name=proc_op.get("process_name", ""),
                process_id=proc_op.get("process_id", 0),
                parent_id=proc_op.get("parent_id"),
                command_line=proc_op.get("command_line")
            ))
        
        # Parse network operations
        for net_op in behavior_data.get("network_operations", []):
            self.network_operations.append(NetworkOperation(
                timestamp=net_op.get("timestamp", ""),
                operation=net_op.get("operation", ""),
                destination=net_op.get("destination", ""),
                port=net_op.get("port"),
                protocol=net_op.get("protocol"),
                data=net_op.get("data")
            ))
    
    def _analyze_behaviors(self) -> Dict[str, Any]:
        """Analyze collected behaviors and generate summary"""
        summary = {
            "total_file_operations": len(self.file_operations),
            "total_registry_operations": len(self.registry_operations),
            "total_process_operations": len(self.process_operations),
            "total_network_operations": len(self.network_operations),
            "ransomware_indicators": [],
            "persistence_indicators": [],
            "evasion_indicators": [],
            "network_indicators": []
        }
        
        # Analyze file operations for ransomware behavior
        encrypted_count = len([
            f for f in self.file_operations 
            if f.operation == "encrypt" or 
            any(ext in f.path.lower() for ext in ['.locked', '.encrypted', '.crypt'])
        ])
        
        if encrypted_count > 10:
            summary["ransomware_indicators"].append({
                "indicator": "mass_file_encryption",
                "count": encrypted_count,
                "severity": "critical"
            })
        
        # Check for ransom note
        ransom_note_patterns = ['readme', 'restore', 'decrypt', 'ransom', 'help']
        for file_op in self.file_operations:
            if file_op.operation == "create":
                if any(p in file_op.path.lower() for p in ransom_note_patterns):
                    summary["ransomware_indicators"].append({
                        "indicator": "ransom_note_created",
                        "path": file_op.path,
                        "severity": "critical"
                    })
                    break
        
        # Analyze registry operations for persistence
        persistence_keys = [
            "CurrentVersion\\Run",
            "CurrentVersion\\RunOnce",
            "Startup",
            "Services"
        ]
        
        for reg_op in self.registry_operations:
            if any(key in reg_op.key for key in persistence_keys):
                summary["persistence_indicators"].append({
                    "indicator": "registry_persistence",
                    "key": reg_op.key,
                    "value": reg_op.value_data,
                    "severity": "high"
                })
        
        # Analyze process operations for evasion
        evasion_commands = ['vssadmin', 'wmic', 'bcdedit', 'wbadmin']
        
        for proc_op in self.process_operations:
            cmd = (proc_op.command_line or "").lower()
            if any(e in cmd for e in evasion_commands):
                if 'shadow' in cmd or 'delete' in cmd:
                    summary["evasion_indicators"].append({
                        "indicator": "shadow_copy_deletion",
                        "command": proc_op.command_line,
                        "severity": "critical"
                    })
                elif 'recoveryenabled' in cmd:
                    summary["evasion_indicators"].append({
                        "indicator": "recovery_disabled",
                        "command": proc_op.command_line,
                        "severity": "high"
                    })
        
        # Analyze network operations
        for net_op in self.network_operations:
            if 'onion' in net_op.destination:
                summary["network_indicators"].append({
                    "indicator": "tor_communication",
                    "destination": net_op.destination,
                    "severity": "high"
                })
            elif net_op.operation == "http" and net_op.data:
                if net_op.data.get("method") == "POST":
                    summary["network_indicators"].append({
                        "indicator": "data_exfiltration",
                        "destination": net_op.destination,
                        "severity": "high"
                    })
        
        return summary
    
    def _extract_indicators(self) -> List[Dict[str, Any]]:
        """Extract IOCs from analysis"""
        indicators = []
        
        # File IOCs
        for file_op in self.file_operations:
            if file_op.operation in ["create", "encrypt"]:
                indicators.append({
                    "type": "file",
                    "value": file_op.path,
                    "operation": file_op.operation
                })
        
        # Registry IOCs
        for reg_op in self.registry_operations:
            indicators.append({
                "type": "registry",
                "value": reg_op.key,
                "operation": reg_op.operation
            })
        
        # Network IOCs
        for net_op in self.network_operations:
            indicators.append({
                "type": "network",
                "value": net_op.destination,
                "port": net_op.port,
                "protocol": net_op.protocol
            })
        
        # Process IOCs
        suspicious_processes = ['vssadmin', 'wmic', 'bcdedit', 'powershell', 'cmd']
        for proc_op in self.process_operations:
            if any(sp in proc_op.process_name.lower() for sp in suspicious_processes):
                indicators.append({
                    "type": "process",
                    "value": proc_op.process_name,
                    "command_line": proc_op.command_line
                })
        
        return indicators


# Standalone analysis function
async def analyze_dynamically(file_path: str, sample_id: str) -> Dict[str, Any]:
    """Perform dynamic analysis on a file"""
    analyzer = DynamicAnalyzer(file_path, sample_id)
    return await analyzer.analyze()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_path> [sample_id]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    sample_id = sys.argv[2] if len(sys.argv) > 2 else "test-sample"
    
    async def main():
        results = await analyze_dynamically(file_path, sample_id)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
