"""
Hash calculation utilities for malware analysis
"""

import os
import hashlib
from typing import Dict, Optional, BinaryIO
from dataclasses import dataclass

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False


@dataclass
class FileHashes:
    """Container for file hashes"""
    md5: str
    sha1: str
    sha256: str
    sha512: str
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    imphash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


class HashCalculator:
    """
    Calculate various hashes for malware analysis
    """
    
    CHUNK_SIZE = 8192  # Read in 8KB chunks for large files
    
    def __init__(self, file_path: str = None, content: bytes = None):
        self.file_path = file_path
        self.content = content
        self._cached_content = None
    
    def _get_content(self) -> bytes:
        """Get file content (cached)"""
        if self._cached_content:
            return self._cached_content
        
        if self.content:
            self._cached_content = self.content
        elif self.file_path:
            with open(self.file_path, 'rb') as f:
                self._cached_content = f.read()
        else:
            raise ValueError("No file path or content provided")
        
        return self._cached_content
    
    def calculate_all(self) -> FileHashes:
        """Calculate all supported hashes"""
        content = self._get_content()
        
        hashes = FileHashes(
            md5=hashlib.md5(content).hexdigest(),
            sha1=hashlib.sha1(content).hexdigest(),
            sha256=hashlib.sha256(content).hexdigest(),
            sha512=hashlib.sha512(content).hexdigest()
        )
        
        # Fuzzy hashes
        if SSDEEP_AVAILABLE:
            try:
                hashes.ssdeep = ssdeep.hash(content)
            except:
                pass
        
        if TLSH_AVAILABLE:
            try:
                hashes.tlsh = tlsh.hash(content)
            except:
                pass
        
        # Import hash (for PE files)
        hashes.imphash = self._calculate_imphash()
        
        return hashes
    
    def calculate_md5(self) -> str:
        """Calculate MD5 hash"""
        return hashlib.md5(self._get_content()).hexdigest()
    
    def calculate_sha1(self) -> str:
        """Calculate SHA1 hash"""
        return hashlib.sha1(self._get_content()).hexdigest()
    
    def calculate_sha256(self) -> str:
        """Calculate SHA256 hash"""
        return hashlib.sha256(self._get_content()).hexdigest()
    
    def calculate_sha512(self) -> str:
        """Calculate SHA512 hash"""
        return hashlib.sha512(self._get_content()).hexdigest()
    
    def _calculate_imphash(self) -> Optional[str]:
        """Calculate import hash for PE files"""
        try:
            import pefile
            if self.file_path:
                pe = pefile.PE(self.file_path)
            else:
                pe = pefile.PE(data=self._get_content())
            
            imphash = pe.get_imphash()
            pe.close()
            return imphash
        except:
            return None
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash for a file efficiently (streaming)
        """
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(HashCalculator.CHUNK_SIZE), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def verify_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file matches expected hash
        """
        calculated = HashCalculator.calculate_file_hash(file_path, algorithm)
        return calculated.lower() == expected_hash.lower()
    
    @staticmethod
    def compare_fuzzy(hash1: str, hash2: str) -> int:
        """
        Compare two ssdeep fuzzy hashes
        Returns similarity score (0-100)
        """
        if not SSDEEP_AVAILABLE:
            return -1
        
        try:
            return ssdeep.compare(hash1, hash2)
        except:
            return -1


def calculate_hashes(file_path: str) -> Dict[str, str]:
    """Simple function to calculate all hashes"""
    calculator = HashCalculator(file_path)
    return calculator.calculate_all().to_dict()


def quick_hash(file_path: str) -> str:
    """Get SHA256 hash quickly"""
    return HashCalculator.calculate_file_hash(file_path, 'sha256')


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python hashes.py <file_path>")
        sys.exit(1)
    
    hashes = calculate_hashes(sys.argv[1])
    print(json.dumps(hashes, indent=2))
