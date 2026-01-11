# 🔬 Ransomware Behavior Analyzer

A comprehensive automated malware analysis sandbox for detecting and analyzing ransomware behavior. Similar to VirusTotal and Cuckoo Sandbox, this tool provides static and dynamic analysis capabilities with professional threat reports.

## 🎯 Features

- **Static Analysis**: PE file parsing, string extraction, YARA rule scanning, hash calculation
- **Dynamic Analysis**: File system monitoring, registry tracking, process monitoring, network capture
- **Sandboxed Execution**: Isolated VM environments (QEMU, VirtualBox, Docker)
- **MITRE ATT&CK Mapping**: Automatic mapping of behaviors to ATT&CK framework
- **Professional Reports**: JSON, PDF, HTML, and Markdown report generation
- **Web Interface**: Modern dashboard for file upload and report viewing
- **YARA Rules**: Comprehensive ruleset for ransomware detection

## 📁 Project Structure

```
VIR/
├── backend/                # FastAPI backend server
│   ├── main.py            # API endpoints
│   ├── config.py          # Configuration settings
│   ├── database.py        # SQLite database operations
│   └── tasks.py           # Background task management
│
├── static_analysis/        # Static analysis module
│   ├── analyzer.py        # PE file analysis
│   ├── strings.py         # String extraction
│   └── hashes.py          # Hash calculation
│
├── dynamic_analysis/       # Dynamic analysis module
│   ├── analyzer.py        # Runtime behavior analysis
│   └── behavior_monitor.py # System monitoring
│
├── sandbox_controller/     # Sandbox management
│   ├── controller.py      # VM controller
│   └── network_sim.py     # Network simulation
│
├── report_generator/       # Report generation
│   ├── generator.py       # Multi-format reports
│   └── mitre_mapper.py    # ATT&CK mapping
│
├── yara_rules/            # YARA detection rules
│   ├── ransomware_generic.yar
│   ├── ransomware_families.yar
│   └── suspicious_behaviors.yar
│
├── vm_agent/              # In-VM monitoring agent
│   ├── agent.py           # Main agent
│   └── utils.py           # Helper utilities
│
├── frontend/              # Web interface
│   ├── index.html         # Main page
│   ├── css/styles.css     # Styling
│   └── js/
│       ├── api.js         # API client
│       └── app.js         # Application logic
│
└── docs/                  # Documentation
    └── ...
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- pip (Python package manager)
- Optional: QEMU/VirtualBox for sandbox execution
- Optional: Docker for containerized analysis

### Installation

1. **Clone/Download the project**:
   ```bash
   cd D:\VIR
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize database**:
   ```bash
   python -c "from backend.database import init_db; import asyncio; asyncio.run(init_db())"
   ```

5. **Start the backend**:
   ```bash
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

6. **Open the frontend**:
   Open `frontend/index.html` in your browser, or serve it:
   ```bash
   cd frontend
   python -m http.server 3000
   ```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/upload` | Upload file for analysis |
| POST | `/api/analyze/{sample_id}` | Start analysis |
| GET | `/api/status/{sample_id}` | Get analysis status |
| GET | `/api/report/{sample_id}` | Get analysis report |
| GET | `/api/samples` | List all samples |
| DELETE | `/api/samples/{sample_id}` | Delete sample |
| GET | `/api/stats` | Get statistics |
| GET | `/api/demo/report` | Get demo report |

## 🔍 Analysis Workflow

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Upload    │────▶│  Static Analysis │────▶│ Dynamic Analysis │
│    File     │     │  (PE, Strings,   │     │  (Sandbox        │
└─────────────┘     │   YARA, Hashes)  │     │   Execution)     │
                    └─────────────────┘     └─────────────────┘
                                                      │
                                                      ▼
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Report    │◀────│  MITRE ATT&CK   │◀────│    Behavior     │
│  Generation │     │    Mapping      │     │   Extraction    │
└─────────────┘     └─────────────────┘     └─────────────────┘
```

## 🛡️ Detected Ransomware Families

- **LockBit** - Including variants 2.0, 3.0
- **REvil/Sodinokibi** - Major RaaS operation
- **Conti** - Enterprise-targeting ransomware
- **Ryuk** - High-profile attacks
- **WannaCry** - SMB-spreading worm
- **DarkSide** - Colonial Pipeline attacker
- **BlackCat/ALPHV** - Rust-based ransomware
- **Maze** - Double extortion pioneer
- **Phobos** - RDP-targeting variant
- **Dharma/CrySis** - Long-running family

## 🎯 MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Execution | T1059, T1106, T1204 |
| Persistence | T1547, T1053, T1136 |
| Defense Evasion | T1027, T1055, T1070 |
| Discovery | T1083, T1082, T1057 |
| Impact | T1486, T1490, T1489 |
| Command & Control | T1071, T1573, T1095 |

## ⚙️ Configuration

Edit `backend/config.py` to customize:

```python
# Analysis settings
SANDBOX_TYPE = "mock"  # Options: qemu, virtualbox, docker, mock
SANDBOX_TIMEOUT = 120  # Analysis timeout in seconds

# Storage paths
SAMPLES_DIR = "./samples"
REPORTS_DIR = "./reports"

# Feature toggles
ENABLE_STATIC_ANALYSIS = True
ENABLE_DYNAMIC_ANALYSIS = True
ENABLE_NETWORK_CAPTURE = False
```

## 🧪 Testing

Run the demo mode to test without actual malware:

```bash
# Backend with demo mode
python backend/main.py --demo

# VM Agent simulation
python vm_agent/agent.py --sample-id test001 --simulate --output test_report.json
```

## ⚠️ Security Warnings

1. **ONLY analyze files in isolated environments**
2. **Never run on production systems**
3. **Use air-gapped networks when possible**
4. **Snapshot VMs before analysis**
5. **Review all YARA rules before deployment**

## 📊 Sample Report Output

```json
{
  "sample_id": "abc123",
  "filename": "invoice.exe",
  "sha256": "e3b0c44298fc1c...",
  "threat_type": "Ransomware",
  "family": "LockBit",
  "confidence": 0.87,
  "risk_level": "CRITICAL",
  "static_analysis": {
    "suspicious_apis": ["CryptEncrypt", "CryptDecrypt"],
    "yara_matches": ["ransomware_lockbit"]
  },
  "dynamic_analysis": {
    "files_encrypted": 1245,
    "shadow_deleted": true,
    "persistence": true
  },
  "mitre_attack": [
    {"technique": "T1486", "name": "Data Encrypted for Impact"}
  ],
  "recommendations": [
    "Isolate affected systems immediately"
  ]
}
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is for educational and authorized security research only. Use responsibly.

## 📞 Support

For issues and questions:
- Create a GitHub issue
- Contact the security team

---

**⚠️ DISCLAIMER**: This tool is designed for legitimate security research and malware analysis by authorized professionals. Misuse of this tool for illegal activities is strictly prohibited. Always obtain proper authorization before analyzing any files.
