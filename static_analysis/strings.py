"""
String extraction utilities for static analysis
"""

import re
import os
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass


@dataclass
class ExtractedString:
    """Represents an extracted string with metadata"""
    value: str
    offset: int
    encoding: str
    category: str = "unknown"
    score: int = 0


class StringExtractor:
    """
    Advanced string extraction from binary files
    """
    
    # Categories of interesting strings
    CATEGORIES = {
        "url": [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'ftp://[^\s<>"{}|\\^`\[\]]+',
        ],
        "ip_address": [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        ],
        "domain": [
            r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b',
        ],
        "email": [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        "file_path": [
            r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*',
            r'/(?:[^/\0]+/)*[^/\0]+',
        ],
        "registry_key": [
            r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)',
            r'SOFTWARE\\[^\s]+',
        ],
        "bitcoin_address": [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            r'\bbc1[ac-hj-np-z02-9]{39,59}\b',
        ],
        "api_function": [
            r'\b(?:Create|Open|Read|Write|Delete|Query|Set|Get|Load|Free)[A-Z][a-zA-Z]+[AW]?\b',
        ],
        "dll_name": [
            r'\b[a-zA-Z0-9_]+\.dll\b',
        ],
        "crypto_artifact": [
            r'\b(?:AES|RSA|DES|3DES|SHA|MD5|HMAC)\b',
            r'-----BEGIN [A-Z]+ KEY-----',
        ],
        "ransomware_indicator": [
            r'(?i)encrypt|decrypt|ransom|bitcoin|wallet|payment|restore|files',
            r'(?i)your files have been',
            r'\.locked\b|\.encrypted\b|\.crypt\b',
        ]
    }
    
    def __init__(self, file_path: str, min_length: int = 4, max_length: int = 500):
        self.file_path = file_path
        self.min_length = min_length
        self.max_length = max_length
        self.strings: List[ExtractedString] = []
        
    def extract(self) -> List[ExtractedString]:
        """Extract all strings from file"""
        self.strings = []
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            return [ExtractedString(f"Error: {e}", 0, "error")]
        
        # Extract ASCII strings
        self._extract_ascii(content)
        
        # Extract Unicode (UTF-16LE) strings
        self._extract_unicode(content)
        
        # Categorize strings
        self._categorize_strings()
        
        # Score strings
        self._score_strings()
        
        return self.strings
    
    def _extract_ascii(self, content: bytes):
        """Extract ASCII strings"""
        pattern = rb'[\x20-\x7e]{' + str(self.min_length).encode() + rb',}'
        
        for match in re.finditer(pattern, content):
            value = match.group().decode('ascii', errors='ignore')
            if len(value) <= self.max_length:
                self.strings.append(ExtractedString(
                    value=value,
                    offset=match.start(),
                    encoding='ascii'
                ))
    
    def _extract_unicode(self, content: bytes):
        """Extract UTF-16LE strings"""
        pattern = rb'(?:[\x20-\x7e]\x00){' + str(self.min_length).encode() + rb',}'
        
        for match in re.finditer(pattern, content):
            try:
                value = match.group().decode('utf-16le', errors='ignore')
                if len(value) <= self.max_length:
                    self.strings.append(ExtractedString(
                        value=value,
                        offset=match.start(),
                        encoding='utf-16le'
                    ))
            except:
                continue
    
    def _categorize_strings(self):
        """Categorize extracted strings"""
        for string in self.strings:
            for category, patterns in self.CATEGORIES.items():
                for pattern in patterns:
                    if re.search(pattern, string.value, re.IGNORECASE):
                        string.category = category
                        break
                if string.category != "unknown":
                    break
    
    def _score_strings(self):
        """Score strings based on their potential importance"""
        category_scores = {
            "ransomware_indicator": 100,
            "crypto_artifact": 80,
            "bitcoin_address": 90,
            "registry_key": 60,
            "url": 50,
            "ip_address": 40,
            "api_function": 30,
            "file_path": 20,
            "dll_name": 20,
            "email": 30,
            "domain": 25,
            "unknown": 0
        }
        
        for string in self.strings:
            string.score = category_scores.get(string.category, 0)
    
    def get_by_category(self, category: str) -> List[ExtractedString]:
        """Get strings by category"""
        return [s for s in self.strings if s.category == category]
    
    def get_suspicious(self, min_score: int = 30) -> List[ExtractedString]:
        """Get strings with score above threshold"""
        return sorted(
            [s for s in self.strings if s.score >= min_score],
            key=lambda x: x.score,
            reverse=True
        )
    
    def get_unique_values(self) -> Set[str]:
        """Get unique string values"""
        return set(s.value for s in self.strings)
    
    def get_summary(self) -> Dict[str, int]:
        """Get count summary by category"""
        summary = {}
        for string in self.strings:
            summary[string.category] = summary.get(string.category, 0) + 1
        return summary


def extract_strings(file_path: str, min_length: int = 4) -> List[str]:
    """Simple function to extract string values"""
    extractor = StringExtractor(file_path, min_length)
    strings = extractor.extract()
    return [s.value for s in strings]


def find_suspicious_strings(file_path: str) -> List[Dict]:
    """Find and return suspicious strings"""
    extractor = StringExtractor(file_path)
    extractor.extract()
    
    suspicious = extractor.get_suspicious()
    return [
        {
            "value": s.value,
            "category": s.category,
            "offset": hex(s.offset),
            "score": s.score
        }
        for s in suspicious
    ]


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python strings.py <file_path>")
        sys.exit(1)
    
    results = find_suspicious_strings(sys.argv[1])
    print(json.dumps(results, indent=2))
