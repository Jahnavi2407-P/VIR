"""
Database models and operations for Ransomware Behavior Analyzer
"""

import os
import json
import aiosqlite
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path

from .config import settings


@dataclass
class SampleRecord:
    """Sample database record"""
    sample_id: str
    filename: str
    file_path: str
    sha256: str
    file_size: int
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    threat_level: Optional[str] = None
    threat_type: Optional[str] = None
    family: Optional[str] = None
    confidence: Optional[float] = None
    report_path: Optional[str] = None
    error_message: Optional[str] = None


class Database:
    """Async SQLite database handler"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = None
    
    async def connect(self):
        """Establish database connection"""
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._create_tables()
    
    async def close(self):
        """Close database connection"""
        if self._connection:
            await self._connection.close()
    
    async def _create_tables(self):
        """Create required database tables"""
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                sample_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER,
                status TEXT DEFAULT 'uploaded',
                submitted_at TIMESTAMP,
                completed_at TIMESTAMP,
                threat_level TEXT,
                threat_type TEXT,
                family TEXT,
                confidence REAL,
                report_path TEXT,
                error_message TEXT
            )
        """)
        
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                result_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sample_id) REFERENCES samples(sample_id)
            )
        """)
        
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                FOREIGN KEY (sample_id) REFERENCES samples(sample_id)
            )
        """)
        
        await self._connection.commit()
    
    async def insert_sample(self, record: SampleRecord) -> bool:
        """Insert new sample record"""
        try:
            await self._connection.execute("""
                INSERT INTO samples (
                    sample_id, filename, file_path, sha256, file_size,
                    status, submitted_at, completed_at, threat_level,
                    threat_type, family, confidence, report_path, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.sample_id, record.filename, record.file_path,
                record.sha256, record.file_size, record.status,
                record.submitted_at, record.completed_at, record.threat_level,
                record.threat_type, record.family, record.confidence,
                record.report_path, record.error_message
            ))
            await self._connection.commit()
            return True
        except Exception as e:
            print(f"Database insert error: {e}")
            return False
    
    async def get_sample(self, sample_id: str) -> Optional[SampleRecord]:
        """Get sample by ID"""
        cursor = await self._connection.execute(
            "SELECT * FROM samples WHERE sample_id = ?",
            (sample_id,)
        )
        row = await cursor.fetchone()
        
        if row:
            return SampleRecord(
                sample_id=row['sample_id'],
                filename=row['filename'],
                file_path=row['file_path'],
                sha256=row['sha256'],
                file_size=row['file_size'],
                status=row['status'],
                submitted_at=datetime.fromisoformat(row['submitted_at']) if row['submitted_at'] else None,
                completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
                threat_level=row['threat_level'],
                threat_type=row['threat_type'],
                family=row['family'],
                confidence=row['confidence'],
                report_path=row['report_path'],
                error_message=row['error_message']
            )
        return None
    
    async def update_status(self, sample_id: str, status: str, **kwargs):
        """Update sample status"""
        updates = ["status = ?"]
        values = [status]
        
        for key, value in kwargs.items():
            if key in ['threat_level', 'threat_type', 'family', 'confidence', 
                      'report_path', 'error_message', 'completed_at']:
                updates.append(f"{key} = ?")
                values.append(value)
        
        values.append(sample_id)
        
        await self._connection.execute(
            f"UPDATE samples SET {', '.join(updates)} WHERE sample_id = ?",
            values
        )
        await self._connection.commit()
    
    async def list_samples(
        self, 
        limit: int = 50, 
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[SampleRecord]:
        """List samples with pagination"""
        query = "SELECT * FROM samples"
        params = []
        
        if status:
            query += " WHERE status = ?"
            params.append(status)
        
        query += " ORDER BY submitted_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor = await self._connection.execute(query, params)
        rows = await cursor.fetchall()
        
        return [
            SampleRecord(
                sample_id=row['sample_id'],
                filename=row['filename'],
                file_path=row['file_path'],
                sha256=row['sha256'],
                file_size=row['file_size'],
                status=row['status'],
                submitted_at=datetime.fromisoformat(row['submitted_at']) if row['submitted_at'] else None,
                completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
                threat_level=row['threat_level'],
                threat_type=row['threat_type'],
                family=row['family'],
                confidence=row['confidence'],
                report_path=row['report_path'],
                error_message=row['error_message']
            )
            for row in rows
        ]
    
    async def delete_sample(self, sample_id: str) -> bool:
        """Delete sample record"""
        try:
            await self._connection.execute(
                "DELETE FROM indicators WHERE sample_id = ?",
                (sample_id,)
            )
            await self._connection.execute(
                "DELETE FROM analysis_results WHERE sample_id = ?",
                (sample_id,)
            )
            await self._connection.execute(
                "DELETE FROM samples WHERE sample_id = ?",
                (sample_id,)
            )
            await self._connection.commit()
            return True
        except Exception as e:
            print(f"Database delete error: {e}")
            return False
    
    async def save_analysis_result(
        self, 
        sample_id: str, 
        analysis_type: str, 
        result_data: Dict[str, Any]
    ):
        """Save analysis result"""
        await self._connection.execute("""
            INSERT INTO analysis_results (sample_id, analysis_type, result_data)
            VALUES (?, ?, ?)
        """, (sample_id, analysis_type, json.dumps(result_data)))
        await self._connection.commit()
    
    async def add_indicator(
        self,
        sample_id: str,
        indicator_type: str,
        indicator_value: str,
        severity: str = "medium",
        description: str = ""
    ):
        """Add an indicator of compromise"""
        await self._connection.execute("""
            INSERT INTO indicators (sample_id, indicator_type, indicator_value, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (sample_id, indicator_type, indicator_value, severity, description))
        await self._connection.commit()
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        stats = {}
        
        # Total samples
        cursor = await self._connection.execute("SELECT COUNT(*) FROM samples")
        stats['total'] = (await cursor.fetchone())[0]
        
        # By status
        cursor = await self._connection.execute(
            "SELECT status, COUNT(*) FROM samples GROUP BY status"
        )
        status_counts = await cursor.fetchall()
        stats['analyzed'] = sum(c[1] for c in status_counts if c[0] in ['completed', 'analyzed'])
        stats['pending'] = sum(c[1] for c in status_counts if c[0] in ['uploaded', 'analyzing'])
        
        # By threat level
        cursor = await self._connection.execute(
            "SELECT threat_level, COUNT(*) FROM samples WHERE threat_level IS NOT NULL GROUP BY threat_level"
        )
        threat_counts = await cursor.fetchall()
        stats['malicious'] = sum(c[1] for c in threat_counts if c[0] in ['HIGH', 'CRITICAL'])
        stats['clean'] = sum(c[1] for c in threat_counts if c[0] == 'LOW')
        
        # By threat type
        cursor = await self._connection.execute(
            "SELECT threat_type, COUNT(*) FROM samples WHERE threat_type IS NOT NULL GROUP BY threat_type"
        )
        stats['by_threat_type'] = {row[0]: row[1] for row in await cursor.fetchall()}
        
        # By family
        cursor = await self._connection.execute(
            "SELECT family, COUNT(*) FROM samples WHERE family IS NOT NULL GROUP BY family"
        )
        stats['by_family'] = {row[0]: row[1] for row in await cursor.fetchall()}
        
        return stats


# Global database instance
_db_instance: Optional[Database] = None


async def init_db():
    """Initialize database"""
    global _db_instance
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    _db_instance = Database(db_path)
    await _db_instance.connect()


async def get_db() -> Database:
    """Get database instance"""
    global _db_instance
    if _db_instance is None:
        await init_db()
    return _db_instance
