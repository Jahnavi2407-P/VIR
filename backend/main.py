"""
Ransomware Behavior Analyzer - Main API Server
FastAPI backend for malware analysis sandbox
"""

import os
import uuid
import asyncio
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import aiofiles

from .config import settings
from .database import init_db, get_db, SampleRecord
from .tasks import analyze_sample_task

app = FastAPI(
    title="Ransomware Behavior Analyzer",
    description="Automated malware analysis sandbox for ransomware detection",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)


# Pydantic models
class AnalysisRequest(BaseModel):
    sample_id: str
    analysis_type: str = "full"  # full, static, dynamic


class AnalysisResponse(BaseModel):
    sample_id: str
    status: str
    message: str


class SampleInfo(BaseModel):
    sample_id: str
    filename: str
    sha256: str
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime]
    threat_level: Optional[str]
    threat_type: Optional[str]
    family: Optional[str]


class ReportSummary(BaseModel):
    sample_id: str
    threat_type: str
    family: str
    confidence: float
    risk_level: str
    static_indicators: List[str]
    dynamic_indicators: List[str]
    mitre_techniques: List[str]


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    await init_db()
    print("🚀 Ransomware Behavior Analyzer API started")
    print(f"📁 Upload directory: {settings.UPLOAD_DIR}")
    print(f"📊 Reports directory: {settings.REPORTS_DIR}")


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "Ransomware Behavior Analyzer",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "upload": "/api/upload",
            "analyze": "/api/analyze",
            "status": "/api/status/{sample_id}",
            "report": "/api/report/{sample_id}",
            "samples": "/api/samples"
        }
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/upload", response_model=AnalysisResponse)
async def upload_sample(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Upload a suspicious file for analysis
    Supported formats: .exe, .dll, .zip, .bin
    """
    # Validate file extension
    allowed_extensions = {'.exe', '.dll', '.zip', '.bin', '.ps1', '.vbs', '.js', '.bat'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported. Allowed: {', '.join(allowed_extensions)}"
        )
    
    # Generate unique sample ID
    sample_id = str(uuid.uuid4())
    
    # Save file
    file_path = os.path.join(settings.UPLOAD_DIR, f"{sample_id}{file_ext}")
    
    try:
        async with aiofiles.open(file_path, 'wb') as out_file:
            content = await file.read()
            await out_file.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    # Calculate hash
    import hashlib
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    # Create database record
    db = await get_db()
    record = SampleRecord(
        sample_id=sample_id,
        filename=file.filename,
        file_path=file_path,
        sha256=sha256_hash,
        file_size=len(content),
        status="uploaded",
        submitted_at=datetime.utcnow()
    )
    await db.insert_sample(record)
    
    # Start background analysis
    if background_tasks:
        background_tasks.add_task(analyze_sample_task, sample_id, file_path)
    
    return AnalysisResponse(
        sample_id=sample_id,
        status="uploaded",
        message=f"File uploaded successfully. SHA256: {sha256_hash}"
    )


@app.post("/api/analyze/{sample_id}", response_model=AnalysisResponse)
async def start_analysis(
    sample_id: str,
    analysis_type: str = "full",
    background_tasks: BackgroundTasks = None
):
    """Start or restart analysis for a sample"""
    db = await get_db()
    sample = await db.get_sample(sample_id)
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Update status
    await db.update_status(sample_id, "analyzing")
    
    # Start background analysis
    if background_tasks:
        background_tasks.add_task(
            analyze_sample_task, 
            sample_id, 
            sample.file_path,
            analysis_type
        )
    
    return AnalysisResponse(
        sample_id=sample_id,
        status="analyzing",
        message=f"Analysis started ({analysis_type})"
    )


@app.get("/api/status/{sample_id}")
async def get_analysis_status(sample_id: str):
    """Get current analysis status"""
    db = await get_db()
    sample = await db.get_sample(sample_id)
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    return {
        "sample_id": sample_id,
        "filename": sample.filename,
        "sha256": sample.sha256,
        "status": sample.status,
        "submitted_at": sample.submitted_at.isoformat(),
        "completed_at": sample.completed_at.isoformat() if sample.completed_at else None,
        "threat_level": sample.threat_level,
        "threat_type": sample.threat_type,
        "family": sample.family
    }


@app.get("/api/report/{sample_id}")
async def get_report(sample_id: str, format: str = "json"):
    """
    Get analysis report
    Formats: json, pdf, html
    """
    db = await get_db()
    sample = await db.get_sample(sample_id)
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if sample.status not in ["completed", "analyzed"]:
        raise HTTPException(
            status_code=400,
            detail=f"Analysis not complete. Current status: {sample.status}"
        )
    
    report_path = os.path.join(settings.REPORTS_DIR, f"{sample_id}.json")
    
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    if format == "json":
        return FileResponse(
            report_path,
            media_type="application/json",
            filename=f"report_{sample_id}.json"
        )
    elif format == "pdf":
        pdf_path = os.path.join(settings.REPORTS_DIR, f"{sample_id}.pdf")
        if os.path.exists(pdf_path):
            return FileResponse(
                pdf_path,
                media_type="application/pdf",
                filename=f"report_{sample_id}.pdf"
            )
        raise HTTPException(status_code=404, detail="PDF report not generated")
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use: json, pdf")


@app.get("/api/samples", response_model=List[SampleInfo])
async def list_samples(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None
):
    """List all analyzed samples"""
    db = await get_db()
    samples = await db.list_samples(limit=limit, offset=offset, status=status)
    
    return [
        SampleInfo(
            sample_id=s.sample_id,
            filename=s.filename,
            sha256=s.sha256,
            status=s.status,
            submitted_at=s.submitted_at,
            completed_at=s.completed_at,
            threat_level=s.threat_level,
            threat_type=s.threat_type,
            family=s.family
        )
        for s in samples
    ]


@app.delete("/api/samples/{sample_id}")
async def delete_sample(sample_id: str):
    """Delete a sample and its artifacts"""
    db = await get_db()
    sample = await db.get_sample(sample_id)
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Delete files
    if os.path.exists(sample.file_path):
        os.remove(sample.file_path)
    
    report_path = os.path.join(settings.REPORTS_DIR, f"{sample_id}.json")
    if os.path.exists(report_path):
        os.remove(report_path)
    
    # Delete database record
    await db.delete_sample(sample_id)
    
    return {"status": "deleted", "sample_id": sample_id}


@app.get("/api/stats")
async def get_statistics():
    """Get analysis statistics"""
    db = await get_db()
    stats = await db.get_statistics()
    
    return {
        "total_samples": stats.get("total", 0),
        "analyzed": stats.get("analyzed", 0),
        "pending": stats.get("pending", 0),
        "malicious": stats.get("malicious", 0),
        "clean": stats.get("clean", 0),
        "by_threat_type": stats.get("by_threat_type", {}),
        "by_family": stats.get("by_family", {})
    }


# Demo endpoint for pre-recorded results
@app.get("/api/demo/report")
async def get_demo_report():
    """Get a demo report for showcase purposes"""
    demo_report = {
        "sample_id": "demo-lockbit-001",
        "filename": "invoice_2024.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
        "threat_type": "Ransomware",
        "family": "LockBit",
        "confidence": 0.87,
        "risk_level": "CRITICAL",
        "static_analysis": {
            "file_type": "PE32 executable",
            "entry_point": "0x00401000",
            "imports": [
                "CryptEncrypt",
                "CryptDecrypt", 
                "CreateFileW",
                "WriteFile",
                "RegSetValueExW"
            ],
            "suspicious_strings": [
                "YOUR FILES HAVE BEEN ENCRYPTED",
                ".locked",
                "http://lockbit*.onion",
                "Bitcoin wallet"
            ],
            "yara_matches": ["ransomware_lockbit", "crypto_api"]
        },
        "dynamic_analysis": {
            "files_encrypted": 1245,
            "registry_modifications": 3,
            "network_connections": 2,
            "processes_created": 5,
            "file_operations": [
                {"action": "encrypt", "pattern": "*.docx → *.docx.locked"},
                {"action": "create", "path": "README_RESTORE.txt"},
                {"action": "delete", "target": "Shadow Copies"}
            ],
            "registry_operations": [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "action": "set"},
                {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", "action": "modify"}
            ],
            "network_activity": [
                {"type": "dns", "query": "lockbit.onion"},
                {"type": "http", "method": "POST", "url": "/key_exchange", "ip": "185.xxx.xxx.xxx"}
            ]
        },
        "mitre_attack": [
            {"technique": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
            {"technique": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
            {"technique": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
            {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
        ],
        "recommendations": [
            "Isolate affected systems immediately",
            "Check for lateral movement indicators",
            "Preserve system memory for forensics",
            "Contact incident response team"
        ]
    }
    
    return demo_report


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
