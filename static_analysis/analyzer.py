"""
Static Analysis Module for Ransomware Behavior Analyzer
Analyzes PE files without execution
"""

import os
import re
import hashlib
import struct
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


class StaticAnalyzer:
    """
    Static analysis engine for PE files
    Extracts metadata, imports, strings, and applies YARA rules
    """
    
    # Suspicious API calls commonly used by malware
    SUSPICIOUS_APIS = {
        # Crypto APIs (Ransomware)
        "CryptEncrypt": "encryption",
        "CryptDecrypt": "encryption",
        "CryptGenKey": "encryption",
        "CryptAcquireContext": "encryption",
        "CryptCreateHash": "encryption",
        "BCryptEncrypt": "encryption",
        "BCryptDecrypt": "encryption",
        
        # File operations
        "CreateFileW": "file_access",
        "CreateFileA": "file_access",
        "WriteFile": "file_access",
        "ReadFile": "file_access",
        "DeleteFileW": "file_access",
        "DeleteFileA": "file_access",
        "MoveFileW": "file_access",
        "CopyFileW": "file_access",
        
        # Registry operations
        "RegSetValueExW": "registry",
        "RegSetValueExA": "registry",
        "RegCreateKeyExW": "registry",
        "RegDeleteKeyW": "registry",
        "RegOpenKeyExW": "registry",
        
        # Process operations
        "CreateProcessW": "process",
        "CreateProcessA": "process",
        "OpenProcess": "process",
        "VirtualAllocEx": "process_injection",
        "WriteProcessMemory": "process_injection",
        "CreateRemoteThread": "process_injection",
        "NtCreateThreadEx": "process_injection",
        
        # Network operations
        "InternetOpenW": "network",
        "InternetConnectW": "network",
        "HttpOpenRequestW": "network",
        "HttpSendRequestW": "network",
        "WSAStartup": "network",
        "socket": "network",
        "connect": "network",
        "send": "network",
        "recv": "network",
        
        # Privilege escalation
        "AdjustTokenPrivileges": "privilege",
        "OpenProcessToken": "privilege",
        "LookupPrivilegeValueW": "privilege",
        
        # Anti-analysis
        "IsDebuggerPresent": "anti_analysis",
        "CheckRemoteDebuggerPresent": "anti_analysis",
        "NtQueryInformationProcess": "anti_analysis",
        "GetTickCount": "anti_analysis",
        "QueryPerformanceCounter": "anti_analysis",
        
        # Credential theft
        "CredReadW": "credential_access",
        "LsaRetrievePrivateData": "credential_access",
    }
    
    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = [
        # Ransom notes
        (r'YOUR FILES (HAVE BEEN|ARE) ENCRYPTED', 'ransom_note'),
        (r'decrypt.*files', 'ransom_note'),
        (r'bitcoin.*wallet', 'ransom_note'),
        (r'ransom', 'ransom_note'),
        (r'payment.*required', 'ransom_note'),
        
        # File extensions
        (r'\.(locked|encrypted|crypt|enc)\b', 'encrypted_extension'),
        (r'\.lockbit', 'lockbit_extension'),
        (r'\.revil', 'revil_extension'),
        (r'\.conti', 'conti_extension'),
        
        # URLs and IPs
        (r'https?://[^\s<>"{}|\\^`\[\]]+', 'url'),
        (r'\.onion', 'tor_url'),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'ip_address'),
        
        # Command execution
        (r'cmd\.exe', 'cmd_reference'),
        (r'powershell', 'powershell_reference'),
        (r'vssadmin.*delete', 'shadow_delete'),
        (r'wmic.*shadowcopy', 'shadow_delete'),
        (r'bcdedit.*recoveryenabled', 'recovery_disable'),
        
        # Registry paths
        (r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'persistence_registry'),
        (r'HKEY_CURRENT_USER', 'registry_reference'),
        (r'HKEY_LOCAL_MACHINE', 'registry_reference'),
        
        # Crypto keywords
        (r'\bAES\b', 'crypto_reference'),
        (r'\bRSA\b', 'crypto_reference'),
        (r'CryptoAPI', 'crypto_reference'),
    ]
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.results = {}
        
    async def analyze(self) -> Dict[str, Any]:
        """
        Perform complete static analysis
        """
        self.results = {
            "file_path": self.file_path,
            "file_name": os.path.basename(self.file_path),
            "analysis_time": datetime.utcnow().isoformat(),
            "file_info": {},
            "hashes": {},
            "pe_info": {},
            "imports": [],
            "exports": [],
            "sections": [],
            "strings": [],
            "suspicious_strings": [],
            "suspicious_imports": [],
            "yara_matches": [],
            "indicators": [],
            "risk_score": 0
        }
        
        # Calculate hashes
        self.results["hashes"] = await self._calculate_hashes()
        
        # Get file type info
        self.results["file_info"] = self._get_file_info()
        
        # PE analysis (if applicable)
        if self._is_pe_file():
            pe_results = self._analyze_pe()
            self.results.update(pe_results)
        
        # Extract strings
        self.results["strings"] = self._extract_strings()
        
        # Find suspicious strings
        self.results["suspicious_strings"] = self._find_suspicious_strings()
        
        # Apply YARA rules
        self.results["yara_matches"] = await self._apply_yara_rules()
        
        # Calculate risk score
        self.results["risk_score"] = self._calculate_risk_score()
        
        # Generate indicators summary
        self.results["indicators"] = self._generate_indicators()
        
        return self.results
    
    async def _calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
                hashes['sha512'] = hashlib.sha512(content).hexdigest()
                
                # SSDeep fuzzy hash (if available)
                try:
                    import ssdeep
                    hashes['ssdeep'] = ssdeep.hash(content)
                except ImportError:
                    pass
                    
        except Exception as e:
            hashes['error'] = str(e)
            
        return hashes
    
    def _get_file_info(self) -> Dict[str, Any]:
        """Get basic file information"""
        info = {
            "size": self.file_size,
            "size_human": self._human_readable_size(self.file_size)
        }
        
        # File type detection
        if MAGIC_AVAILABLE:
            try:
                info["magic_type"] = magic.from_file(self.file_path)
                info["mime_type"] = magic.from_file(self.file_path, mime=True)
            except:
                pass
        
        # Manual detection based on header
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(16)
                
            if header[:2] == b'MZ':
                info["file_type"] = "PE executable"
            elif header[:4] == b'\x7fELF':
                info["file_type"] = "ELF executable"
            elif header[:4] == b'PK\x03\x04':
                info["file_type"] = "ZIP archive"
            elif header[:3] == b'Rar':
                info["file_type"] = "RAR archive"
            elif header[:5] == b'%PDF-':
                info["file_type"] = "PDF document"
            else:
                info["file_type"] = "Unknown"
                
        except Exception as e:
            info["error"] = str(e)
            
        return info
    
    def _is_pe_file(self) -> bool:
        """Check if file is a PE executable"""
        try:
            with open(self.file_path, 'rb') as f:
                return f.read(2) == b'MZ'
        except:
            return False
    
    def _analyze_pe(self) -> Dict[str, Any]:
        """Analyze PE file structure"""
        results = {
            "pe_info": {},
            "imports": [],
            "exports": [],
            "sections": [],
            "suspicious_imports": []
        }
        
        if not PEFILE_AVAILABLE:
            results["pe_info"]["error"] = "pefile module not installed"
            return results
        
        try:
            pe = pefile.PE(self.file_path)
            
            # Basic PE info
            results["pe_info"] = {
                "machine": self._get_machine_type(pe.FILE_HEADER.Machine),
                "timestamp": datetime.utcfromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp
                ).isoformat() if pe.FILE_HEADER.TimeDateStamp else None,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": self._get_subsystem(pe.OPTIONAL_HEADER.Subsystem),
                "dll": pe.FILE_HEADER.IMAGE_FILE_DLL,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "characteristics": self._parse_characteristics(pe.FILE_HEADER.Characteristics)
            }
            
            # Check for packing
            results["pe_info"]["packed"] = self._check_packed(pe)
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            results["imports"].append(func_name)
                            
                            # Check for suspicious imports
                            if func_name in self.SUSPICIOUS_APIS:
                                results["suspicious_imports"].append({
                                    "function": func_name,
                                    "dll": dll_name,
                                    "category": self.SUSPICIOUS_APIS[func_name]
                                })
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        results["exports"].append(
                            exp.name.decode('utf-8', errors='ignore')
                        )
            
            # Sections
            for section in pe.sections:
                sec_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy(),
                    "characteristics": self._parse_section_characteristics(
                        section.Characteristics
                    )
                }
                
                # High entropy might indicate packing/encryption
                if sec_info["entropy"] > 7.0:
                    sec_info["suspicious"] = "High entropy (possibly packed/encrypted)"
                    
                results["sections"].append(sec_info)
            
            pe.close()
            
        except Exception as e:
            results["pe_info"]["error"] = str(e)
            
        return results
    
    def _extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings from file"""
        strings = []
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            # ASCII strings
            ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, content)
            strings.extend(s.decode('ascii', errors='ignore') for s in ascii_strings)
            
            # Unicode strings (UTF-16LE)
            unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, content)
            strings.extend(
                s.decode('utf-16le', errors='ignore') 
                for s in unicode_strings
            )
            
            # Deduplicate and limit
            strings = list(set(strings))[:1000]
            
        except Exception as e:
            strings = [f"Error extracting strings: {e}"]
            
        return strings
    
    def _find_suspicious_strings(self) -> List[Dict[str, str]]:
        """Find suspicious strings based on patterns"""
        suspicious = []
        
        all_strings = ' '.join(self.results.get("strings", []))
        
        for pattern, category in self.SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, all_strings, re.IGNORECASE)
            for match in matches[:10]:  # Limit matches per pattern
                suspicious.append({
                    "string": match,
                    "category": category,
                    "pattern": pattern
                })
        
        return suspicious
    
    async def _apply_yara_rules(self) -> List[Dict[str, Any]]:
        """Apply YARA rules to the file"""
        matches = []
        
        if not YARA_AVAILABLE:
            return [{"error": "yara-python not installed"}]
        
        # Find YARA rules directory
        yara_dir = Path(__file__).parent.parent / "yara_rules"
        
        if not yara_dir.exists():
            return [{"error": "YARA rules directory not found"}]
        
        try:
            # Compile all rule files
            rule_files = list(yara_dir.glob("*.yar")) + list(yara_dir.glob("*.yara"))
            
            for rule_file in rule_files:
                try:
                    rules = yara.compile(filepath=str(rule_file))
                    file_matches = rules.match(self.file_path)
                    
                    for match in file_matches:
                        matches.append({
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": list(match.tags),
                            "meta": dict(match.meta) if match.meta else {},
                            "strings": [
                                {
                                    "offset": s[0],
                                    "identifier": s[1],
                                    "data": s[2].decode('utf-8', errors='ignore')[:50]
                                }
                                for s in match.strings[:5]  # Limit string matches
                            ]
                        })
                except Exception as e:
                    matches.append({
                        "rule_file": str(rule_file),
                        "error": str(e)
                    })
                    
        except Exception as e:
            matches.append({"error": str(e)})
            
        return matches
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Suspicious imports
        import_categories = set()
        for imp in self.results.get("suspicious_imports", []):
            import_categories.add(imp.get("category"))
        
        category_scores = {
            "encryption": 20,
            "process_injection": 25,
            "anti_analysis": 15,
            "credential_access": 20,
            "privilege": 15,
            "network": 10,
            "registry": 10,
            "file_access": 5,
            "process": 5
        }
        
        for category in import_categories:
            score += category_scores.get(category, 5)
        
        # Suspicious strings
        string_categories = set()
        for s in self.results.get("suspicious_strings", []):
            string_categories.add(s.get("category"))
        
        string_scores = {
            "ransom_note": 30,
            "encrypted_extension": 20,
            "shadow_delete": 25,
            "recovery_disable": 20,
            "tor_url": 15,
            "persistence_registry": 15,
            "crypto_reference": 10,
            "powershell_reference": 10
        }
        
        for category in string_categories:
            score += string_scores.get(category, 5)
        
        # YARA matches
        yara_matches = self.results.get("yara_matches", [])
        for match in yara_matches:
            if not match.get("error"):
                rule_name = match.get("rule", "").lower()
                if "ransomware" in rule_name:
                    score += 30
                elif "malware" in rule_name:
                    score += 20
                elif "suspicious" in rule_name:
                    score += 10
        
        # Packed binary
        if self.results.get("pe_info", {}).get("packed"):
            score += 15
        
        # High entropy sections
        for section in self.results.get("sections", []):
            if section.get("entropy", 0) > 7.5:
                score += 10
                break
        
        return min(score, 100)
    
    def _generate_indicators(self) -> List[Dict[str, str]]:
        """Generate list of indicators found"""
        indicators = []
        
        # Import-based indicators
        for imp in self.results.get("suspicious_imports", []):
            indicators.append({
                "type": "import",
                "value": imp["function"],
                "category": imp["category"],
                "severity": "high" if imp["category"] in ["encryption", "process_injection"] else "medium"
            })
        
        # String-based indicators
        for s in self.results.get("suspicious_strings", []):
            indicators.append({
                "type": "string",
                "value": s["string"][:100],
                "category": s["category"],
                "severity": "high" if s["category"] in ["ransom_note", "shadow_delete"] else "medium"
            })
        
        # YARA-based indicators
        for match in self.results.get("yara_matches", []):
            if not match.get("error"):
                indicators.append({
                    "type": "yara",
                    "value": match.get("rule"),
                    "category": "signature",
                    "severity": "high"
                })
        
        return indicators
    
    # Helper methods
    def _human_readable_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def _get_machine_type(self, machine: int) -> str:
        machines = {
            0x014c: "i386",
            0x8664: "AMD64",
            0x01c0: "ARM",
            0xaa64: "ARM64"
        }
        return machines.get(machine, hex(machine))
    
    def _get_subsystem(self, subsystem: int) -> str:
        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI (Console)",
            5: "OS/2 CUI",
            7: "POSIX CUI",
            9: "Windows CE GUI",
            10: "EFI Application"
        }
        return subsystems.get(subsystem, str(subsystem))
    
    def _parse_characteristics(self, characteristics: int) -> List[str]:
        flags = []
        char_flags = {
            0x0001: "RELOCS_STRIPPED",
            0x0002: "EXECUTABLE_IMAGE",
            0x0020: "LARGE_ADDRESS_AWARE",
            0x0100: "32BIT_MACHINE",
            0x0200: "DEBUG_STRIPPED",
            0x2000: "DLL"
        }
        for flag, name in char_flags.items():
            if characteristics & flag:
                flags.append(name)
        return flags
    
    def _parse_section_characteristics(self, characteristics: int) -> List[str]:
        flags = []
        char_flags = {
            0x00000020: "CODE",
            0x00000040: "INITIALIZED_DATA",
            0x00000080: "UNINITIALIZED_DATA",
            0x20000000: "EXECUTE",
            0x40000000: "READ",
            0x80000000: "WRITE"
        }
        for flag, name in char_flags.items():
            if characteristics & flag:
                flags.append(name)
        return flags
    
    def _check_packed(self, pe) -> bool:
        """Check if PE is likely packed"""
        # Check for common packer sections
        packer_sections = ['.upx', '.aspack', '.petite', '.nspack', 'UPX']
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if any(ps.lower() in name.lower() for ps in packer_sections):
                return True
        
        # Check entropy
        high_entropy_count = 0
        for section in pe.sections:
            if section.get_entropy() > 7.0:
                high_entropy_count += 1
        
        # If most sections have high entropy, likely packed
        if high_entropy_count > len(pe.sections) * 0.5:
            return True
        
        return False


# Async wrapper for standalone use
async def analyze_file(file_path: str) -> Dict[str, Any]:
    """Standalone function to analyze a file"""
    analyzer = StaticAnalyzer(file_path)
    return await analyzer.analyze()


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_path>")
        sys.exit(1)
    
    async def main():
        results = await analyze_file(sys.argv[1])
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
