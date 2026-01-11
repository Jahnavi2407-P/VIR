# Architecture Documentation

## System Overview

The Ransomware Behavior Analyzer is a modular malware analysis platform designed for security researchers and blue team operators.

## Architecture Diagram

```
                                    ┌─────────────────────────────────────┐
                                    │           Web Frontend              │
                                    │    (HTML/CSS/JavaScript)            │
                                    └─────────────────┬───────────────────┘
                                                      │
                                                      │ HTTP/REST
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Backend API (FastAPI)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Upload    │  │   Status    │  │   Report    │  │       Demo          │ │
│  │  Endpoint   │  │  Endpoint   │  │  Endpoint   │  │     Endpoint        │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
              ▼                           ▼                           ▼
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│   Static Analysis   │     │   Dynamic Analysis  │     │   Report Generator  │
│                     │     │                     │     │                     │
│  ┌───────────────┐  │     │  ┌───────────────┐  │     │  ┌───────────────┐  │
│  │ PE Parser     │  │     │  │ File Monitor  │  │     │  │ JSON Export   │  │
│  ├───────────────┤  │     │  ├───────────────┤  │     │  ├───────────────┤  │
│  │ String Extract│  │     │  │ Reg Monitor   │  │     │  │ HTML Export   │  │
│  ├───────────────┤  │     │  ├───────────────┤  │     │  ├───────────────┤  │
│  │ YARA Scanner  │  │     │  │ Proc Monitor  │  │     │  │ PDF Export    │  │
│  ├───────────────┤  │     │  ├───────────────┤  │     │  ├───────────────┤  │
│  │ Hash Calc     │  │     │  │ Net Monitor   │  │     │  │ MITRE Mapper  │  │
│  └───────────────┘  │     │  └───────────────┘  │     │  └───────────────┘  │
└─────────────────────┘     └──────────┬──────────┘     └─────────────────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │  Sandbox Controller │
                            │                     │
                            │  ┌───────────────┐  │
                            │  │ QEMU Backend  │  │
                            │  ├───────────────┤  │
                            │  │ VBox Backend  │  │
                            │  ├───────────────┤  │
                            │  │Docker Backend │  │
                            │  ├───────────────┤  │
                            │  │ Mock Backend  │  │
                            │  └───────────────┘  │
                            └──────────┬──────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │     Sandbox VM      │
                            │                     │
                            │  ┌───────────────┐  │
                            │  │   VM Agent    │  │
                            │  │  (Monitoring) │  │
                            │  └───────────────┘  │
                            └─────────────────────┘
```

## Component Details

### 1. Web Frontend
- Single-page application (SPA)
- File upload with drag-and-drop
- Real-time status updates
- Interactive report viewer
- MITRE ATT&CK visualization

### 2. Backend API
- **Framework**: FastAPI
- **Database**: SQLite with aiosqlite
- **Features**:
  - Async request handling
  - File validation
  - Task queuing
  - Report caching

### 3. Static Analysis Module
Analyzes files without execution:
- **PE Parser**: Extracts headers, sections, imports
- **String Extractor**: Finds suspicious strings/URLs
- **YARA Scanner**: Matches against rule database
- **Hash Calculator**: MD5, SHA1, SHA256, imphash

### 4. Dynamic Analysis Module
Monitors runtime behavior:
- **File Monitor**: Tracks file operations (create/modify/delete)
- **Registry Monitor**: Watches registry changes (Windows)
- **Process Monitor**: Tracks process creation/injection
- **Network Monitor**: Captures DNS/HTTP/TCP traffic

### 5. Sandbox Controller
Manages isolated execution environments:
- **QEMU**: Full system emulation
- **VirtualBox**: Hardware virtualization
- **Docker**: Container-based isolation
- **Mock**: Simulated analysis for testing

### 6. Report Generator
Produces professional reports:
- **JSON**: Machine-readable format
- **HTML**: Interactive web report
- **PDF**: Printable document
- **Markdown**: Documentation-friendly

### 7. VM Agent
Runs inside sandbox for monitoring:
- System call interception
- API hooking
- Behavior logging
- Report transmission

## Data Flow

```
1. User uploads file via Web UI
          │
          ▼
2. Backend validates & stores file
          │
          ▼
3. Static analysis runs (parallel)
   - Hash calculation
   - PE parsing
   - String extraction
   - YARA scanning
          │
          ▼
4. Sandbox prepares VM
   - Snapshot creation
   - Agent injection
   - Network isolation
          │
          ▼
5. Dynamic analysis runs
   - Sample execution
   - Behavior monitoring
   - Network capture
          │
          ▼
6. Agent collects data
   - File operations
   - Registry changes
   - Process activity
   - Network traffic
          │
          ▼
7. Analysis results combined
          │
          ▼
8. MITRE ATT&CK mapping
          │
          ▼
9. Report generation
          │
          ▼
10. Results displayed in UI
```

## Security Considerations

### Isolation
- VMs run in isolated networks
- No internet access during analysis
- Simulated services for malware triggers

### Data Handling
- Samples stored encrypted at rest
- Automatic cleanup after retention period
- Secure deletion of temporary files

### Access Control
- API authentication (production)
- Role-based permissions
- Audit logging

## Scalability

### Horizontal Scaling
```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Backend  │   │ Backend  │   │ Backend  │
        │   #1     │   │   #2     │   │   #3     │
        └────┬─────┘   └────┬─────┘   └────┬─────┘
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                    ┌───────────────┐
                    │   Shared DB   │
                    │  (PostgreSQL) │
                    └───────────────┘
```

### Task Queue
```
┌──────────┐     ┌─────────────┐     ┌──────────────┐
│ Backends │────▶│    Redis    │────▶│   Workers    │
│          │     │   Queue     │     │   (Celery)   │
└──────────┘     └─────────────┘     └──────────────┘
```

## Future Enhancements

1. **Machine Learning Integration**
   - Behavioral classification
   - Variant detection
   - Anomaly detection

2. **Memory Forensics**
   - RAM dump analysis
   - Process injection detection
   - Rootkit detection

3. **Network Analysis**
   - Full PCAP analysis
   - C2 protocol detection
   - Domain reputation

4. **Integration APIs**
   - VirusTotal integration
   - Threat intelligence feeds
   - SIEM connectors
