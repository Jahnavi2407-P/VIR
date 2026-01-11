# Setup Guide

## Prerequisites

### Required Software
- Python 3.9 or higher
- pip (Python package manager)
- Git (optional, for version control)

### Optional Software
- **VirtualBox 7.0+**: For VirtualBox sandbox backend
- **QEMU 7.0+**: For QEMU sandbox backend
- **Docker**: For container-based analysis

### System Requirements
- **Minimum**: 4GB RAM, 2 CPU cores, 20GB disk
- **Recommended**: 16GB RAM, 4+ CPU cores, 100GB SSD

## Installation Steps

### 1. Clone/Download Project

```bash
# If using Git
git clone <repository-url> D:\VIR
cd D:\VIR

# Or download and extract to D:\VIR
```

### 2. Create Virtual Environment

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Installing YARA (Optional but Recommended)

**Windows:**
1. Download pre-built YARA from releases
2. Install `yara-python`:
   ```bash
   pip install yara-python
   ```

**Linux:**
```bash
sudo apt-get install yara
pip install yara-python
```

**macOS:**
```bash
brew install yara
pip install yara-python
```

### 4. Initialize Database

```bash
python -c "from backend.database import init_db; import asyncio; asyncio.run(init_db())"
```

### 5. Create Required Directories

```bash
mkdir samples reports logs
```

### 6. Configure Application

Edit `backend/config.py`:

```python
# Set your preferred sandbox type
SANDBOX_TYPE = "mock"  # Start with mock for testing

# Adjust paths if needed
SAMPLES_DIR = "D:/VIR/samples"
REPORTS_DIR = "D:/VIR/reports"

# Set analysis timeout
SANDBOX_TIMEOUT = 120
```

## Running the Application

### Start Backend Server

```bash
cd D:\VIR\backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`
API docs at: `http://localhost:8000/docs`

### Start Frontend (Development)

Option 1 - Direct file access:
```
Open D:\VIR\frontend\index.html in a web browser
```

Option 2 - Local HTTP server:
```bash
cd D:\VIR\frontend
python -m http.server 3000
```
Then open: `http://localhost:3000`

## Sandbox Setup (Optional)

### VirtualBox Setup

1. Install VirtualBox
2. Create a Windows 10/11 VM:
   - Name: `malware-sandbox`
   - RAM: 4GB
   - Disk: 40GB
   - Network: Host-only adapter

3. Install VM Agent:
   ```bash
   # Copy vm_agent folder to VM
   # Inside VM:
   pip install -r requirements.txt
   ```

4. Create snapshot named "clean"

5. Update config:
   ```python
   SANDBOX_TYPE = "virtualbox"
   VBOX_VM_NAME = "malware-sandbox"
   ```

### QEMU Setup

1. Install QEMU
2. Create a disk image:
   ```bash
   qemu-img create -f qcow2 sandbox.qcow2 40G
   ```

3. Install Windows and agent

4. Update config:
   ```python
   SANDBOX_TYPE = "qemu"
   QEMU_IMAGE_PATH = "path/to/sandbox.qcow2"
   ```

### Docker Setup

1. Install Docker Desktop
2. Build analysis container:
   ```bash
   # From VIR directory
   docker build -t malware-sandbox -f Dockerfile.sandbox .
   ```

3. Update config:
   ```python
   SANDBOX_TYPE = "docker"
   ```

## Verification

### Test Backend

```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

### Test Static Analysis

```bash
curl http://localhost:8000/api/demo/report
```

### Test Upload

```bash
curl -X POST -F "file=@test.txt" http://localhost:8000/api/upload
```

## Troubleshooting

### Common Issues

**1. Port already in use**
```bash
# Find process using port 8000
netstat -ano | findstr :8000
# Kill the process or use different port
uvicorn main:app --port 8001
```

**2. Module not found errors**
```bash
# Ensure virtual environment is activated
.\venv\Scripts\Activate.ps1

# Reinstall dependencies
pip install -r requirements.txt
```

**3. YARA not working**
```bash
# Check YARA installation
python -c "import yara; print('YARA OK')"

# If fails, reinstall
pip uninstall yara-python
pip install yara-python
```

**4. Database errors**
```bash
# Reset database
del malware_samples.db
python -c "from backend.database import init_db; import asyncio; asyncio.run(init_db())"
```

**5. Permission errors**
```bash
# Run as administrator (Windows)
# Or fix permissions (Linux)
chmod -R 755 D:/VIR
```

## Production Deployment

### Using Gunicorn (Linux)

```bash
pip install gunicorn
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### Using Docker

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t ransomware-analyzer .
docker run -p 8000:8000 ransomware-analyzer
```

### Using Nginx (Reverse Proxy)

```nginx
server {
    listen 80;
    server_name analyzer.example.com;

    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        root /var/www/analyzer/frontend;
        index index.html;
    }
}
```

## Security Hardening

1. **Enable HTTPS**
2. **Set up authentication**
3. **Configure firewall rules**
4. **Isolate sandbox network**
5. **Enable audit logging**
6. **Regular updates**
