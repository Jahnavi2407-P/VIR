# API Reference

## Overview

The Ransomware Behavior Analyzer API provides endpoints for uploading suspicious files, triggering analysis, and retrieving results.

**Base URL:** `http://localhost:8000/api`

## Authentication

Currently, the API is open for development. In production, implement:
- API key authentication
- OAuth 2.0
- JWT tokens

## Endpoints

---

### Health Check

Check if the API is running.

**Request:**
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

### Upload File

Upload a file for analysis.

**Request:**
```http
POST /upload
Content-Type: multipart/form-data
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| file | file | Yes | The file to analyze |

**Example:**
```bash
curl -X POST -F "file=@suspicious.exe" http://localhost:8000/api/upload
```

**Response:**
```json
{
  "sample_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "uploaded",
  "message": "File uploaded successfully. SHA256: e3b0c44..."
}
```

**Error Responses:**
- `400`: Invalid file type
- `413`: File too large
- `500`: Server error

---

### Start Analysis

Begin analysis of an uploaded sample.

**Request:**
```http
POST /analyze/{sample_id}?analysis_type={type}
```

**Path Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sample_id | string | UUID of the uploaded sample |

**Query Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| analysis_type | string | full | Type: `static`, `dynamic`, or `full` |

**Example:**
```bash
curl -X POST "http://localhost:8000/api/analyze/550e8400-e29b-41d4-a716-446655440000?analysis_type=full"
```

**Response:**
```json
{
  "sample_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "analyzing",
  "message": "Analysis started"
}
```

---

### Get Status

Get the current analysis status.

**Request:**
```http
GET /status/{sample_id}
```

**Example:**
```bash
curl http://localhost:8000/api/status/550e8400-e29b-41d4-a716-446655440000
```

**Response:**
```json
{
  "sample_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "suspicious.exe",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "status": "completed",
  "threat_type": "Ransomware",
  "family": "LockBit",
  "threat_level": "CRITICAL",
  "submitted_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:32:00Z"
}
```

**Status Values:**
- `uploaded`: File received, waiting for analysis
- `analyzing`: Analysis in progress
- `completed`: Analysis finished
- `error`: Analysis failed

---

### Get Report

Retrieve the full analysis report.

**Request:**
```http
GET /report/{sample_id}?format={format}
```

**Query Parameters:**
| Name | Type | Default | Options |
|------|------|---------|---------|
| format | string | json | `json`, `html`, `pdf`, `markdown` |

**Example:**
```bash
# JSON format
curl http://localhost:8000/api/report/550e8400?format=json

# HTML format
curl http://localhost:8000/api/report/550e8400?format=html -o report.html
```

**Response (JSON):**
```json
{
  "sample_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "suspicious.exe",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "threat_type": "Ransomware",
  "family": "LockBit",
  "confidence": 0.87,
  "risk_level": "CRITICAL",
  "static_analysis": {
    "file_type": "PE32 executable",
    "file_size": 245760,
    "entry_point": "0x00401000",
    "compile_timestamp": "2024-01-10T12:00:00Z",
    "imports": [
      {
        "dll": "KERNEL32.dll",
        "functions": ["CreateFileW", "WriteFile", "DeleteFileW"]
      },
      {
        "dll": "ADVAPI32.dll",
        "functions": ["CryptEncrypt", "CryptDecrypt", "RegSetValueExW"]
      }
    ],
    "suspicious_strings": [
      "YOUR FILES HAVE BEEN ENCRYPTED",
      ".locked",
      "bitcoin wallet"
    ],
    "yara_matches": [
      {
        "rule": "ransomware_lockbit",
        "description": "Detects LockBit ransomware",
        "severity": "critical"
      }
    ],
    "hashes": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
      "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744"
    }
  },
  "dynamic_analysis": {
    "files_encrypted": 1245,
    "files_created": 15,
    "files_deleted": 1245,
    "registry_modifications": 3,
    "processes_created": 5,
    "network_connections": 2,
    "file_operations": [
      {
        "action": "encrypt",
        "path": "C:\\Users\\*\\Documents\\*.docx",
        "extension_added": ".locked"
      },
      {
        "action": "create",
        "path": "C:\\Users\\*\\Desktop\\README_RESTORE.txt"
      },
      {
        "action": "delete",
        "target": "Volume Shadow Copies"
      }
    ],
    "registry_operations": [
      {
        "action": "create",
        "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value": "WindowsUpdate",
        "data": "C:\\ProgramData\\malware.exe"
      }
    ],
    "network_activity": [
      {
        "type": "dns",
        "query": "lockbit.onion"
      },
      {
        "type": "http",
        "method": "POST",
        "url": "/key_exchange",
        "remote_ip": "185.xxx.xxx.xxx"
      }
    ],
    "process_tree": [
      {
        "name": "suspicious.exe",
        "pid": 1234,
        "children": [
          {"name": "cmd.exe", "pid": 2345},
          {"name": "vssadmin.exe", "pid": 3456}
        ]
      }
    ]
  },
  "mitre_attack": [
    {
      "technique": "T1486",
      "name": "Data Encrypted for Impact",
      "tactic": "Impact",
      "description": "Adversaries may encrypt files to deny access"
    },
    {
      "technique": "T1547.001",
      "name": "Registry Run Keys / Startup Folder",
      "tactic": "Persistence",
      "description": "Adversaries may achieve persistence by adding a program to a startup folder"
    },
    {
      "technique": "T1490",
      "name": "Inhibit System Recovery",
      "tactic": "Impact",
      "description": "Adversaries may delete or modify built-in system recovery features"
    }
  ],
  "indicators_of_compromise": {
    "hashes": ["e3b0c44298fc1c149afbf4c8996fb924..."],
    "ips": ["185.xxx.xxx.xxx"],
    "domains": ["lockbit.onion"],
    "mutexes": ["LockBit_Mutex_2024"],
    "file_patterns": ["*.locked", "README_RESTORE.txt"]
  },
  "recommendations": [
    {
      "priority": "critical",
      "action": "Isolate affected systems from network immediately"
    },
    {
      "priority": "high",
      "action": "Check for lateral movement to other systems"
    },
    {
      "priority": "high",
      "action": "Preserve system memory and disk for forensics"
    },
    {
      "priority": "medium",
      "action": "Review backup availability and integrity"
    }
  ],
  "analysis_metadata": {
    "analyzer_version": "1.0.0",
    "analysis_duration_seconds": 120,
    "sandbox_type": "virtualbox",
    "analyzed_at": "2024-01-15T10:32:00Z"
  }
}
```

---

### List Samples

Get a list of all analyzed samples.

**Request:**
```http
GET /samples?limit={limit}&offset={offset}&status={status}
```

**Query Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| limit | int | 50 | Max results to return |
| offset | int | 0 | Pagination offset |
| status | string | null | Filter by status |

**Example:**
```bash
curl "http://localhost:8000/api/samples?limit=10&status=completed"
```

**Response:**
```json
[
  {
    "sample_id": "550e8400-e29b-41d4-a716-446655440000",
    "filename": "suspicious.exe",
    "sha256": "e3b0c44298fc1c...",
    "status": "completed",
    "threat_type": "Ransomware",
    "threat_level": "CRITICAL",
    "submitted_at": "2024-01-15T10:30:00Z"
  },
  {
    "sample_id": "660e8400-e29b-41d4-a716-446655440001",
    "filename": "unknown.dll",
    "sha256": "a1b2c3d4e5f6...",
    "status": "analyzing",
    "threat_type": null,
    "threat_level": null,
    "submitted_at": "2024-01-15T11:00:00Z"
  }
]
```

---

### Delete Sample

Remove a sample and its analysis data.

**Request:**
```http
DELETE /samples/{sample_id}
```

**Example:**
```bash
curl -X DELETE http://localhost:8000/api/samples/550e8400
```

**Response:**
```json
{
  "status": "deleted",
  "sample_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

### Get Statistics

Get analysis statistics.

**Request:**
```http
GET /stats
```

**Response:**
```json
{
  "total_samples": 150,
  "analyzed": 142,
  "pending": 5,
  "errors": 3,
  "threat_breakdown": {
    "ransomware": 45,
    "trojan": 28,
    "worm": 12,
    "clean": 57
  },
  "top_families": [
    {"name": "LockBit", "count": 15},
    {"name": "REvil", "count": 12},
    {"name": "Conti", "count": 8}
  ],
  "daily_submissions": [
    {"date": "2024-01-15", "count": 25},
    {"date": "2024-01-14", "count": 32}
  ]
}
```

---

### Get Demo Report

Get a pre-generated demo report.

**Request:**
```http
GET /demo/report
```

**Response:**
Returns a full sample report (same structure as `/report/{sample_id}`).

---

## Error Handling

All errors follow this format:

```json
{
  "detail": "Error message description"
}
```

**HTTP Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 404 | Not Found |
| 413 | Payload Too Large |
| 429 | Too Many Requests |
| 500 | Internal Server Error |

## Rate Limiting

Default limits (configurable):
- 100 requests per minute per IP
- 10 file uploads per minute per IP
- 1000 API calls per hour per IP

## Webhooks (Future)

Coming soon: Configure webhooks for analysis completion notifications.

```json
{
  "url": "https://your-server.com/webhook",
  "events": ["analysis.completed", "analysis.failed"],
  "secret": "your-webhook-secret"
}
```
