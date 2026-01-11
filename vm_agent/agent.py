"""
VM Agent for Sandbox Monitoring
Runs inside the sandbox VM to capture behavior
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vm_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('VMAgent')


@dataclass
class FileEvent:
    """File system event"""
    timestamp: str
    action: str  # create, modify, delete, read, rename
    path: str
    size: Optional[int] = None
    hash_sha256: Optional[str] = None
    is_encrypted: bool = False


@dataclass
class RegistryEvent:
    """Registry modification event (Windows only)"""
    timestamp: str
    action: str  # create, modify, delete
    key: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None


@dataclass
class ProcessEvent:
    """Process creation/termination event"""
    timestamp: str
    action: str  # create, terminate, inject
    pid: int
    name: str
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None


@dataclass
class NetworkEvent:
    """Network connection event"""
    timestamp: str
    action: str  # connect, listen, send, receive, dns
    protocol: str
    local_address: Optional[str] = None
    local_port: Optional[int] = None
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    data_size: Optional[int] = None


@dataclass
class BehaviorReport:
    """Complete behavior report"""
    sample_id: str
    start_time: str
    end_time: str
    file_events: List[FileEvent] = field(default_factory=list)
    registry_events: List[RegistryEvent] = field(default_factory=list)
    process_events: List[ProcessEvent] = field(default_factory=list)
    network_events: List[NetworkEvent] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)


class FileSystemMonitor:
    """Monitor file system operations"""
    
    # Common ransomware file extensions
    ENCRYPTED_EXTENSIONS = {
        '.locked', '.encrypted', '.crypto', '.locky', '.cerber',
        '.crypt', '.enc', '.crypted', '.lockbit', '.revil', '.ryuk',
        '.conti', '.blackcat', '.dharma', '.phobos', '.maze'
    }
    
    # Important directories to monitor
    WATCH_DIRS = [
        os.path.expanduser('~'),
        'C:\\Users',
        'C:\\ProgramData',
        '/home',
        '/tmp'
    ]
    
    def __init__(self):
        self.events: List[FileEvent] = []
        self.file_hashes: Dict[str, str] = {}
        self.running = False
        
    def start(self):
        """Start monitoring"""
        self.running = True
        logger.info("File system monitor started")
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def record_event(self, action: str, path: str, **kwargs):
        """Record a file event"""
        event = FileEvent(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            path=path,
            **kwargs
        )
        
        # Check if file appears to be encrypted
        if any(path.endswith(ext) for ext in self.ENCRYPTED_EXTENSIONS):
            event.is_encrypted = True
            
        self.events.append(event)
        logger.debug(f"File event: {action} - {path}")
        
    def compute_hash(self, filepath: str) -> Optional[str]:
        """Compute SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None


class RegistryMonitor:
    """Monitor Windows registry operations"""
    
    # Important registry keys to watch
    WATCH_KEYS = [
        r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender',
        r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
    ]
    
    def __init__(self):
        self.events: List[RegistryEvent] = []
        self.running = False
        
    def start(self):
        """Start monitoring"""
        if sys.platform == 'win32':
            self.running = True
            logger.info("Registry monitor started")
        else:
            logger.info("Registry monitoring skipped (not Windows)")
            
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def record_event(self, action: str, key: str, **kwargs):
        """Record a registry event"""
        event = RegistryEvent(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            key=key,
            **kwargs
        )
        self.events.append(event)
        logger.debug(f"Registry event: {action} - {key}")


class ProcessMonitor:
    """Monitor process operations"""
    
    # Suspicious process patterns
    SUSPICIOUS_PROCESSES = {
        'vssadmin', 'wbadmin', 'bcdedit', 'wevtutil',
        'cipher', 'sdelete', 'powershell', 'cmd',
        'certutil', 'bitsadmin', 'mshta', 'wscript', 'cscript'
    }
    
    def __init__(self):
        self.events: List[ProcessEvent] = []
        self.running = False
        self.initial_processes: set = set()
        
    def start(self):
        """Start monitoring"""
        self.running = True
        self._capture_initial_processes()
        logger.info("Process monitor started")
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def _capture_initial_processes(self):
        """Capture initial process list"""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(['tasklist', '/fo', 'csv'], 
                                        capture_output=True, text=True)
                # Parse and store PIDs
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        except Exception as e:
            logger.error(f"Error capturing processes: {e}")
            
    def record_event(self, action: str, pid: int, name: str, **kwargs):
        """Record a process event"""
        event = ProcessEvent(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            pid=pid,
            name=name,
            **kwargs
        )
        self.events.append(event)
        logger.debug(f"Process event: {action} - {name} (PID: {pid})")


class NetworkMonitor:
    """Monitor network operations"""
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit
        5555,   # Common backdoor
        6666,   # Backdoor
        31337,  # Elite
        12345,  # NetBus
    }
    
    def __init__(self):
        self.events: List[NetworkEvent] = []
        self.running = False
        
    def start(self):
        """Start monitoring"""
        self.running = True
        logger.info("Network monitor started")
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
    def record_event(self, action: str, protocol: str, **kwargs):
        """Record a network event"""
        event = NetworkEvent(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            protocol=protocol,
            **kwargs
        )
        self.events.append(event)
        logger.debug(f"Network event: {action} - {protocol}")


class VMAgent:
    """Main VM Agent class"""
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 9999):
        self.server_host = server_host
        self.server_port = server_port
        
        self.file_monitor = FileSystemMonitor()
        self.registry_monitor = RegistryMonitor()
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        
        self.sample_id: Optional[str] = None
        self.start_time: Optional[str] = None
        self.running = False
        
    def start_monitoring(self, sample_id: str):
        """Start all monitors"""
        self.sample_id = sample_id
        self.start_time = datetime.utcnow().isoformat()
        self.running = True
        
        self.file_monitor.start()
        self.registry_monitor.start()
        self.process_monitor.start()
        self.network_monitor.start()
        
        logger.info(f"VM Agent started monitoring sample: {sample_id}")
        
    def stop_monitoring(self) -> BehaviorReport:
        """Stop all monitors and generate report"""
        self.running = False
        
        self.file_monitor.stop()
        self.registry_monitor.stop()
        self.process_monitor.stop()
        self.network_monitor.stop()
        
        report = self._generate_report()
        logger.info("VM Agent stopped monitoring")
        
        return report
        
    def _generate_report(self) -> BehaviorReport:
        """Generate behavior report"""
        report = BehaviorReport(
            sample_id=self.sample_id or 'unknown',
            start_time=self.start_time or datetime.utcnow().isoformat(),
            end_time=datetime.utcnow().isoformat(),
            file_events=self.file_monitor.events,
            registry_events=self.registry_monitor.events,
            process_events=self.process_monitor.events,
            network_events=self.network_monitor.events,
            indicators=self._extract_indicators()
        )
        
        return report
        
    def _extract_indicators(self) -> Dict[str, Any]:
        """Extract behavioral indicators"""
        indicators = {
            'files_encrypted': 0,
            'files_deleted': 0,
            'persistence_mechanisms': [],
            'shadow_copy_deletion': False,
            'suspicious_processes': [],
            'network_connections': [],
            'ransomware_indicators': []
        }
        
        # Analyze file events
        for event in self.file_monitor.events:
            if event.is_encrypted:
                indicators['files_encrypted'] += 1
            if event.action == 'delete':
                indicators['files_deleted'] += 1
                
        # Check for shadow copy deletion
        for event in self.process_monitor.events:
            if 'vssadmin' in event.name.lower():
                if event.command_line and 'delete' in event.command_line.lower():
                    indicators['shadow_copy_deletion'] = True
                    
            if event.name.lower() in ProcessMonitor.SUSPICIOUS_PROCESSES:
                indicators['suspicious_processes'].append(event.name)
                
        # Check for persistence
        for event in self.registry_monitor.events:
            if 'Run' in event.key:
                indicators['persistence_mechanisms'].append({
                    'type': 'registry',
                    'key': event.key
                })
                
        # Ransomware-specific indicators
        if indicators['files_encrypted'] > 10:
            indicators['ransomware_indicators'].append('mass_file_encryption')
        if indicators['shadow_copy_deletion']:
            indicators['ransomware_indicators'].append('shadow_copy_deletion')
        if indicators['persistence_mechanisms']:
            indicators['ransomware_indicators'].append('persistence_established')
            
        return indicators
        
    def send_report(self, report: BehaviorReport) -> bool:
        """Send report to controller"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.server_port))
            
            report_json = json.dumps(asdict(report))
            sock.sendall(report_json.encode('utf-8'))
            
            sock.close()
            logger.info("Report sent to controller")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send report: {e}")
            return False
            
    def save_report(self, report: BehaviorReport, filepath: str):
        """Save report to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(asdict(report), f, indent=2)
            logger.info(f"Report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


class SimulatedBehavior:
    """
    Simulate ransomware-like behavior for testing
    WARNING: Only use in isolated environments!
    """
    
    @staticmethod
    def simulate_file_encryption(agent: VMAgent, count: int = 10):
        """Simulate file encryption events"""
        extensions = ['.docx', '.xlsx', '.pdf', '.jpg', '.txt']
        
        for i in range(count):
            ext = extensions[i % len(extensions)]
            original_path = f"C:\\Users\\Test\\Documents\\file{i}{ext}"
            encrypted_path = f"{original_path}.locked"
            
            agent.file_monitor.record_event('read', original_path)
            agent.file_monitor.record_event('create', encrypted_path, is_encrypted=True)
            agent.file_monitor.record_event('delete', original_path)
            
    @staticmethod
    def simulate_shadow_deletion(agent: VMAgent):
        """Simulate shadow copy deletion"""
        agent.process_monitor.record_event(
            'create',
            pid=5678,
            name='vssadmin.exe',
            command_line='vssadmin delete shadows /all /quiet',
            parent_pid=1234,
            parent_name='malware.exe'
        )
        
    @staticmethod
    def simulate_persistence(agent: VMAgent):
        """Simulate persistence mechanism"""
        agent.registry_monitor.record_event(
            'create',
            key=r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
            value_name='WindowsUpdate',
            value_data=r'C:\Users\Public\malware.exe'
        )
        
    @staticmethod
    def simulate_network_activity(agent: VMAgent):
        """Simulate C2 communication"""
        agent.network_monitor.record_event(
            'dns',
            'udp',
            remote_address='8.8.8.8',
            remote_port=53
        )
        
        agent.network_monitor.record_event(
            'connect',
            'tcp',
            remote_address='185.100.86.100',
            remote_port=443
        )


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='VM Agent for Sandbox Monitoring')
    parser.add_argument('--sample-id', required=True, help='Sample ID to monitor')
    parser.add_argument('--duration', type=int, default=60, help='Monitoring duration (seconds)')
    parser.add_argument('--server', default='localhost', help='Controller server address')
    parser.add_argument('--port', type=int, default=9999, help='Controller server port')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--simulate', action='store_true', help='Run simulation mode')
    
    args = parser.parse_args()
    
    agent = VMAgent(server_host=args.server, server_port=args.port)
    
    try:
        agent.start_monitoring(args.sample_id)
        
        if args.simulate:
            # Run simulation
            logger.info("Running behavior simulation...")
            SimulatedBehavior.simulate_file_encryption(agent, count=50)
            SimulatedBehavior.simulate_shadow_deletion(agent)
            SimulatedBehavior.simulate_persistence(agent)
            SimulatedBehavior.simulate_network_activity(agent)
        else:
            # Wait for specified duration
            logger.info(f"Monitoring for {args.duration} seconds...")
            time.sleep(args.duration)
            
        report = agent.stop_monitoring()
        
        # Save report
        if args.output:
            agent.save_report(report, args.output)
        else:
            agent.save_report(report, f'report_{args.sample_id}.json')
            
        # Try to send to controller
        agent.send_report(report)
        
        # Print summary
        print("\n" + "="*50)
        print("BEHAVIOR SUMMARY")
        print("="*50)
        print(f"Files encrypted: {report.indicators.get('files_encrypted', 0)}")
        print(f"Files deleted: {report.indicators.get('files_deleted', 0)}")
        print(f"Shadow copy deletion: {report.indicators.get('shadow_copy_deletion', False)}")
        print(f"Suspicious processes: {len(report.indicators.get('suspicious_processes', []))}")
        print(f"Ransomware indicators: {report.indicators.get('ransomware_indicators', [])}")
        print("="*50)
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        report = agent.stop_monitoring()
        if args.output:
            agent.save_report(report, args.output)


if __name__ == '__main__':
    main()
