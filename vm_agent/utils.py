"""
VM Agent Utilities
Helper functions for monitoring
"""

import os
import sys
import hashlib
import ctypes
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger('VMAgent.Utils')


def is_admin() -> bool:
    """Check if running with admin privileges"""
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False


def get_file_hash(filepath: str, algorithms: List[str] = ['md5', 'sha1', 'sha256']) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file
    
    Args:
        filepath: Path to file
        algorithms: List of hash algorithms
        
    Returns:
        Dict of algorithm: hash
    """
    hashes = {}
    
    try:
        hashers = {alg: hashlib.new(alg) for alg in algorithms}
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                for hasher in hashers.values():
                    hasher.update(chunk)
                    
        for alg, hasher in hashers.items():
            hashes[alg] = hasher.hexdigest()
            
    except Exception as e:
        logger.error(f"Error hashing file {filepath}: {e}")
        
    return hashes


def get_file_entropy(filepath: str) -> float:
    """
    Calculate file entropy (useful for detecting encryption)
    
    High entropy (>7.5) may indicate encryption
    """
    import math
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0
            
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
            
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
                
        return entropy
        
    except Exception as e:
        logger.error(f"Error calculating entropy for {filepath}: {e}")
        return 0.0


def get_pe_info(filepath: str) -> Optional[Dict]:
    """
    Extract PE file information (Windows executables)
    """
    try:
        import pefile
    except ImportError:
        logger.warning("pefile not installed, PE analysis unavailable")
        return None
        
    try:
        pe = pefile.PE(filepath)
        
        info = {
            'machine': pe.FILE_HEADER.Machine,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'sections': [],
            'imports': [],
            'exports': [],
        }
        
        # Sections
        for section in pe.sections:
            info['sections'].append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
            })
            
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = [imp.name.decode('utf-8', errors='ignore') 
                            for imp in entry.imports if imp.name]
                info['imports'].append({
                    'dll': dll_name,
                    'functions': functions
                })
                
        pe.close()
        return info
        
    except Exception as e:
        logger.error(f"Error analyzing PE {filepath}: {e}")
        return None


def detect_ransomware_note(directory: str) -> List[str]:
    """
    Search for common ransomware ransom notes
    """
    ransom_note_patterns = [
        'readme*.txt', 'read_me*.txt', 'how_to*.txt', 'decrypt*.txt',
        '*decrypt*.html', '*restore*.txt', '*recover*.txt', '*payment*.txt',
        'ransomware*.txt', '*_readme.txt', 'help_decrypt*.txt'
    ]
    
    notes_found = []
    
    try:
        from glob import glob
        
        for pattern in ransom_note_patterns:
            matches = glob(os.path.join(directory, '**', pattern), recursive=True)
            notes_found.extend(matches)
            
    except Exception as e:
        logger.error(f"Error searching for ransom notes: {e}")
        
    return notes_found


def monitor_directory_changes(directory: str, callback) -> None:
    """
    Monitor directory for changes using OS-specific mechanisms
    
    Args:
        directory: Directory to monitor
        callback: Function to call on changes
    """
    if sys.platform == 'win32':
        _monitor_win32(directory, callback)
    else:
        _monitor_linux(directory, callback)


def _monitor_win32(directory: str, callback):
    """Windows directory monitoring using ReadDirectoryChangesW"""
    try:
        import win32file
        import win32con
        
        handle = win32file.CreateFile(
            directory,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        
        actions = {
            1: 'created',
            2: 'deleted',
            3: 'modified',
            4: 'renamed_from',
            5: 'renamed_to'
        }
        
        while True:
            results = win32file.ReadDirectoryChangesW(
                handle,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                None,
                None
            )
            
            for action, file in results:
                full_path = os.path.join(directory, file)
                action_name = actions.get(action, 'unknown')
                callback(action_name, full_path)
                
    except ImportError:
        logger.warning("pywin32 not installed, using fallback monitoring")
        _monitor_fallback(directory, callback)
    except Exception as e:
        logger.error(f"Error in Windows monitoring: {e}")


def _monitor_linux(directory: str, callback):
    """Linux directory monitoring using inotify"""
    try:
        import inotify.adapters
        
        i = inotify.adapters.InotifyTree(directory)
        
        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event
            
            full_path = os.path.join(path, filename)
            action = type_names[0] if type_names else 'unknown'
            
            callback(action.lower(), full_path)
            
    except ImportError:
        logger.warning("inotify not installed, using fallback monitoring")
        _monitor_fallback(directory, callback)
    except Exception as e:
        logger.error(f"Error in Linux monitoring: {e}")


def _monitor_fallback(directory: str, callback):
    """Fallback polling-based monitoring"""
    import time
    
    known_files = {}
    
    while True:
        current_files = {}
        
        try:
            for root, dirs, files in os.walk(directory):
                for f in files:
                    full_path = os.path.join(root, f)
                    try:
                        stat = os.stat(full_path)
                        current_files[full_path] = stat.st_mtime
                    except:
                        pass
                        
            # Check for new files
            for path in current_files:
                if path not in known_files:
                    callback('created', path)
                elif current_files[path] != known_files[path]:
                    callback('modified', path)
                    
            # Check for deleted files
            for path in known_files:
                if path not in current_files:
                    callback('deleted', path)
                    
            known_files = current_files
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Error in fallback monitoring: {e}")
            time.sleep(5)


def get_process_list() -> List[Dict]:
    """Get list of running processes"""
    processes = []
    
    if sys.platform == 'win32':
        try:
            import wmi
            c = wmi.WMI()
            for proc in c.Win32_Process():
                processes.append({
                    'pid': proc.ProcessId,
                    'name': proc.Name,
                    'command_line': proc.CommandLine,
                    'parent_pid': proc.ParentProcessId
                })
        except ImportError:
            import subprocess
            result = subprocess.run(['tasklist', '/v', '/fo', 'csv'], 
                                    capture_output=True, text=True)
            # Parse CSV output
    else:
        import subprocess
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        # Parse ps output
        
    return processes


def get_network_connections() -> List[Dict]:
    """Get active network connections"""
    connections = []
    
    try:
        import psutil
        
        for conn in psutil.net_connections():
            connections.append({
                'fd': conn.fd,
                'family': str(conn.family),
                'type': str(conn.type),
                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status,
                'pid': conn.pid
            })
    except ImportError:
        logger.warning("psutil not installed, network monitoring limited")
        
    return connections
