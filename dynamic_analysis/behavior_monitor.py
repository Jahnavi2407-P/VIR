"""
Behavior Monitor - Tracks runtime behavior during analysis
"""

import os
import json
import time
import threading
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
import queue


@dataclass
class BehaviorEvent:
    """Represents a behavior event"""
    timestamp: str
    event_type: str  # file, registry, process, network
    operation: str
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # info, low, medium, high, critical


class BehaviorMonitor:
    """
    Real-time behavior monitoring during sandbox execution
    Aggregates events from various monitoring sources
    """
    
    def __init__(self):
        self.events: List[BehaviorEvent] = []
        self.event_queue = queue.Queue()
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.callbacks: Dict[str, List[Callable]] = {
            'file': [],
            'registry': [],
            'process': [],
            'network': [],
            'all': []
        }
        
        # Statistics
        self.stats = {
            'file_events': 0,
            'registry_events': 0,
            'process_events': 0,
            'network_events': 0,
            'high_severity_events': 0
        }
    
    def start(self):
        """Start monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._process_events)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop(self) -> List[BehaviorEvent]:
        """Stop monitoring and return collected events"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        return self.events
    
    def add_event(self, event: BehaviorEvent):
        """Add event to processing queue"""
        self.event_queue.put(event)
    
    def add_callback(self, event_type: str, callback: Callable):
        """Register callback for event type"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def _process_events(self):
        """Process events from queue"""
        while self.monitoring or not self.event_queue.empty():
            try:
                event = self.event_queue.get(timeout=0.5)
                self._handle_event(event)
            except queue.Empty:
                continue
    
    def _handle_event(self, event: BehaviorEvent):
        """Handle a single event"""
        self.events.append(event)
        
        # Update statistics
        stat_key = f"{event.event_type}_events"
        if stat_key in self.stats:
            self.stats[stat_key] += 1
        
        if event.severity in ['high', 'critical']:
            self.stats['high_severity_events'] += 1
        
        # Execute callbacks
        for callback in self.callbacks.get(event.event_type, []):
            try:
                callback(event)
            except Exception as e:
                print(f"Callback error: {e}")
        
        for callback in self.callbacks.get('all', []):
            try:
                callback(event)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def get_events_by_type(self, event_type: str) -> List[BehaviorEvent]:
        """Get events filtered by type"""
        return [e for e in self.events if e.event_type == event_type]
    
    def get_events_by_severity(self, severity: str) -> List[BehaviorEvent]:
        """Get events filtered by severity"""
        return [e for e in self.events if e.severity == severity]
    
    def get_high_severity_events(self) -> List[BehaviorEvent]:
        """Get high and critical severity events"""
        return [e for e in self.events if e.severity in ['high', 'critical']]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get monitoring summary"""
        return {
            "total_events": len(self.events),
            "statistics": self.stats,
            "event_types": {
                "file": len(self.get_events_by_type('file')),
                "registry": len(self.get_events_by_type('registry')),
                "process": len(self.get_events_by_type('process')),
                "network": len(self.get_events_by_type('network'))
            },
            "severity_distribution": {
                "info": len(self.get_events_by_severity('info')),
                "low": len(self.get_events_by_severity('low')),
                "medium": len(self.get_events_by_severity('medium')),
                "high": len(self.get_events_by_severity('high')),
                "critical": len(self.get_events_by_severity('critical'))
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Export all events as dictionary"""
        return {
            "events": [
                {
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "operation": e.operation,
                    "data": e.data,
                    "severity": e.severity
                }
                for e in self.events
            ],
            "summary": self.get_summary()
        }


class FileMonitor:
    """
    File system monitoring
    Tracks file operations during malware execution
    """
    
    RANSOMWARE_EXTENSIONS = [
        '.locked', '.encrypted', '.crypt', '.enc', '.crypted',
        '.lockbit', '.revil', '.conti', '.ryuk', '.wannacry'
    ]
    
    SENSITIVE_DIRECTORIES = [
        'Documents', 'Desktop', 'Pictures', 'Downloads',
        'Music', 'Videos', 'OneDrive', 'Dropbox'
    ]
    
    def __init__(self, behavior_monitor: BehaviorMonitor):
        self.monitor = behavior_monitor
        self.file_operations = []
        self.encrypted_files = []
    
    def on_file_create(self, path: str, size: int = 0):
        """Handle file creation"""
        severity = self._assess_file_severity(path, 'create')
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='file',
            operation='create',
            data={
                'path': path,
                'size': size,
                'extension': Path(path).suffix
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.file_operations.append(event)
    
    def on_file_modify(self, path: str, old_size: int = 0, new_size: int = 0):
        """Handle file modification"""
        severity = self._assess_file_severity(path, 'modify')
        
        # Check for encryption (size change + extension change)
        if any(ext in path.lower() for ext in self.RANSOMWARE_EXTENSIONS):
            severity = 'critical'
            self.encrypted_files.append(path)
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='file',
            operation='modify',
            data={
                'path': path,
                'old_size': old_size,
                'new_size': new_size,
                'size_change': new_size - old_size
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.file_operations.append(event)
    
    def on_file_delete(self, path: str):
        """Handle file deletion"""
        severity = self._assess_file_severity(path, 'delete')
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='file',
            operation='delete',
            data={'path': path},
            severity=severity
        )
        self.monitor.add_event(event)
        self.file_operations.append(event)
    
    def on_file_rename(self, old_path: str, new_path: str):
        """Handle file rename (often used in encryption)"""
        severity = 'medium'
        
        # Check if renaming to ransomware extension
        new_ext = Path(new_path).suffix.lower()
        if any(ext in new_ext for ext in self.RANSOMWARE_EXTENSIONS):
            severity = 'critical'
            self.encrypted_files.append(new_path)
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='file',
            operation='rename',
            data={
                'old_path': old_path,
                'new_path': new_path,
                'old_extension': Path(old_path).suffix,
                'new_extension': new_ext
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.file_operations.append(event)
    
    def _assess_file_severity(self, path: str, operation: str) -> str:
        """Assess severity of file operation"""
        path_lower = path.lower()
        
        # Check for sensitive directories
        if any(d.lower() in path_lower for d in self.SENSITIVE_DIRECTORIES):
            if operation in ['delete', 'modify']:
                return 'high'
            return 'medium'
        
        # Check for system files
        if 'windows\\system32' in path_lower:
            return 'high'
        
        # Check for ransom note patterns
        ransom_patterns = ['readme', 'restore', 'decrypt', 'ransom', 'help']
        if any(p in path_lower for p in ransom_patterns):
            return 'high'
        
        return 'low'


class RegistryMonitor:
    """
    Registry monitoring
    Tracks registry operations for persistence and evasion
    """
    
    PERSISTENCE_KEYS = [
        'CurrentVersion\\Run',
        'CurrentVersion\\RunOnce',
        'CurrentVersion\\RunServices',
        'CurrentVersion\\RunServicesOnce',
        'Startup',
        'Services'
    ]
    
    SECURITY_KEYS = [
        'Windows Defender',
        'DisableAntiSpyware',
        'DisableRealtimeMonitoring',
        'SubmitSamplesConsent'
    ]
    
    def __init__(self, behavior_monitor: BehaviorMonitor):
        self.monitor = behavior_monitor
        self.registry_operations = []
    
    def on_registry_set(self, key: str, value_name: str, value_data: Any):
        """Handle registry value set"""
        severity = self._assess_registry_severity(key, 'set')
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='registry',
            operation='set',
            data={
                'key': key,
                'value_name': value_name,
                'value_data': str(value_data)[:500]  # Limit data size
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.registry_operations.append(event)
    
    def on_registry_delete(self, key: str, value_name: str = None):
        """Handle registry deletion"""
        severity = self._assess_registry_severity(key, 'delete')
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='registry',
            operation='delete',
            data={
                'key': key,
                'value_name': value_name
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.registry_operations.append(event)
    
    def _assess_registry_severity(self, key: str, operation: str) -> str:
        """Assess severity of registry operation"""
        key_lower = key.lower()
        
        # Persistence keys
        if any(pk.lower() in key_lower for pk in self.PERSISTENCE_KEYS):
            return 'critical' if operation == 'set' else 'high'
        
        # Security/AV disable
        if any(sk.lower() in key_lower for sk in self.SECURITY_KEYS):
            return 'critical'
        
        return 'medium'


class ProcessMonitor:
    """
    Process monitoring
    Tracks process creation and suspicious commands
    """
    
    SUSPICIOUS_PROCESSES = [
        'vssadmin.exe', 'wmic.exe', 'bcdedit.exe', 'wbadmin.exe',
        'powershell.exe', 'cmd.exe', 'cscript.exe', 'wscript.exe',
        'mshta.exe', 'certutil.exe', 'bitsadmin.exe'
    ]
    
    DANGEROUS_COMMANDS = [
        'delete shadows', 'shadowcopy delete', 'recoveryenabled',
        '-encodedcommand', '-enc ', 'bypass', '-ep bypass',
        'invoke-expression', 'iex ', 'downloadstring'
    ]
    
    def __init__(self, behavior_monitor: BehaviorMonitor):
        self.monitor = behavior_monitor
        self.process_operations = []
        self.process_tree = {}
    
    def on_process_create(self, process_name: str, pid: int, ppid: int, 
                          command_line: str = None):
        """Handle process creation"""
        severity = self._assess_process_severity(process_name, command_line)
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='process',
            operation='create',
            data={
                'process_name': process_name,
                'pid': pid,
                'ppid': ppid,
                'command_line': command_line
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.process_operations.append(event)
        
        # Track process tree
        self.process_tree[pid] = {
            'name': process_name,
            'parent': ppid,
            'command_line': command_line
        }
    
    def on_process_terminate(self, process_name: str, pid: int):
        """Handle process termination"""
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='process',
            operation='terminate',
            data={
                'process_name': process_name,
                'pid': pid
            },
            severity='info'
        )
        self.monitor.add_event(event)
    
    def _assess_process_severity(self, process_name: str, command_line: str) -> str:
        """Assess severity of process operation"""
        name_lower = process_name.lower()
        cmd_lower = (command_line or '').lower()
        
        # Check for dangerous commands
        if any(dc in cmd_lower for dc in self.DANGEROUS_COMMANDS):
            return 'critical'
        
        # Check for suspicious processes
        if any(sp.lower() in name_lower for sp in self.SUSPICIOUS_PROCESSES):
            return 'high'
        
        return 'medium'


class NetworkMonitor:
    """
    Network monitoring
    Tracks network connections and data transfers
    """
    
    SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337, 8888, 9999]
    TOR_INDICATORS = ['.onion', 'tor2web', '9050', '9150']
    
    def __init__(self, behavior_monitor: BehaviorMonitor):
        self.monitor = behavior_monitor
        self.network_operations = []
        self.connections = []
    
    def on_dns_query(self, domain: str, resolved_ips: List[str] = None):
        """Handle DNS query"""
        severity = self._assess_network_severity(domain, 'dns')
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='network',
            operation='dns',
            data={
                'domain': domain,
                'resolved_ips': resolved_ips or []
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.network_operations.append(event)
    
    def on_connect(self, ip: str, port: int, protocol: str = 'tcp'):
        """Handle network connection"""
        severity = self._assess_network_severity(f"{ip}:{port}", 'connect')
        
        if port in self.SUSPICIOUS_PORTS:
            severity = 'high'
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='network',
            operation='connect',
            data={
                'ip': ip,
                'port': port,
                'protocol': protocol
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.network_operations.append(event)
        self.connections.append((ip, port))
    
    def on_http_request(self, method: str, url: str, headers: Dict = None, 
                        body: bytes = None):
        """Handle HTTP request"""
        severity = 'medium'
        
        if method.upper() == 'POST':
            severity = 'high'
        
        event = BehaviorEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='network',
            operation='http',
            data={
                'method': method,
                'url': url,
                'headers': headers,
                'body_size': len(body) if body else 0
            },
            severity=severity
        )
        self.monitor.add_event(event)
        self.network_operations.append(event)
    
    def _assess_network_severity(self, target: str, operation: str) -> str:
        """Assess severity of network operation"""
        target_lower = target.lower()
        
        # Tor indicators
        if any(ti in target_lower for ti in self.TOR_INDICATORS):
            return 'critical'
        
        return 'medium'


if __name__ == "__main__":
    # Demo usage
    monitor = BehaviorMonitor()
    file_monitor = FileMonitor(monitor)
    registry_monitor = RegistryMonitor(monitor)
    process_monitor = ProcessMonitor(monitor)
    network_monitor = NetworkMonitor(monitor)
    
    monitor.start()
    
    # Simulate some events
    file_monitor.on_file_rename(
        "C:\\Users\\test\\Documents\\file.docx",
        "C:\\Users\\test\\Documents\\file.docx.locked"
    )
    
    registry_monitor.on_registry_set(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Malware",
        "C:\\malware.exe"
    )
    
    process_monitor.on_process_create(
        "vssadmin.exe", 1234, 5678,
        "vssadmin delete shadows /all /quiet"
    )
    
    network_monitor.on_dns_query("lockbit.onion")
    
    time.sleep(1)
    events = monitor.stop()
    
    print(json.dumps(monitor.to_dict(), indent=2))
