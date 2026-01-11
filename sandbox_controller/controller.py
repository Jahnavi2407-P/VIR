"""
Sandbox Controller for Ransomware Behavior Analyzer
Manages isolated VM environments for safe malware execution
"""

import os
import json
import asyncio
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from enum import Enum
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.config import settings


class SandboxType(Enum):
    """Supported sandbox types"""
    QEMU = "qemu"
    VIRTUALBOX = "virtualbox"
    DOCKER = "docker"  # Limited for Windows malware
    MOCK = "mock"  # For testing


class SandboxState(Enum):
    """Sandbox state"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    EXECUTING = "executing"
    STOPPING = "stopping"
    ERROR = "error"


class SandboxController:
    """
    Controls sandbox VM for safe malware execution
    Supports QEMU/KVM and VirtualBox
    """
    
    def __init__(
        self,
        sandbox_type: SandboxType = None,
        vm_name: str = None,
        snapshot_name: str = None
    ):
        self.sandbox_type = sandbox_type or SandboxType(settings.SANDBOX_TYPE)
        self.vm_name = vm_name or settings.VM_NAME
        self.snapshot_name = snapshot_name or settings.SANDBOX_SNAPSHOT
        
        self.state = SandboxState.STOPPED
        self.process: Optional[subprocess.Popen] = None
        self.monitoring_data = {}
        
        # Paths
        self.vm_disk = settings.VM_DISK_IMAGE
        self.temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        
        # SSH/RDP connection info (for agent communication)
        self.vm_ip = "192.168.122.100"  # Default libvirt NAT
        self.vm_port = 22
        self.vm_user = "sandbox"
        self.vm_password = "sandbox123"
    
    async def start(self) -> bool:
        """Start the sandbox VM"""
        self.state = SandboxState.STARTING
        
        try:
            if self.sandbox_type == SandboxType.QEMU:
                return await self._start_qemu()
            elif self.sandbox_type == SandboxType.VIRTUALBOX:
                return await self._start_virtualbox()
            elif self.sandbox_type == SandboxType.DOCKER:
                return await self._start_docker()
            elif self.sandbox_type == SandboxType.MOCK:
                return await self._start_mock()
            else:
                raise ValueError(f"Unsupported sandbox type: {self.sandbox_type}")
                
        except Exception as e:
            self.state = SandboxState.ERROR
            raise RuntimeError(f"Failed to start sandbox: {e}")
    
    async def _start_qemu(self) -> bool:
        """Start QEMU/KVM virtual machine"""
        # Restore snapshot first
        restore_cmd = [
            "qemu-img", "snapshot", "-a", self.snapshot_name, self.vm_disk
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *restore_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
        except FileNotFoundError:
            print("Warning: qemu-img not found, skipping snapshot restore")
        
        # Start QEMU
        qemu_cmd = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-m", str(settings.VM_MEMORY),
            "-smp", str(settings.VM_CPUS),
            "-hda", self.vm_disk,
            "-net", "nic",
            "-net", f"user,hostfwd=tcp::{self.vm_port}-:22",
            "-nographic",
            "-monitor", "none"
        ]
        
        try:
            self.process = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for VM to boot
            await asyncio.sleep(30)  # Adjust based on VM boot time
            
            self.state = SandboxState.RUNNING
            return True
            
        except FileNotFoundError:
            raise RuntimeError("QEMU not found. Install qemu-system-x86_64")
    
    async def _start_virtualbox(self) -> bool:
        """Start VirtualBox virtual machine"""
        # Restore snapshot
        restore_cmd = [
            "VBoxManage", "snapshot", self.vm_name,
            "restore", self.snapshot_name
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *restore_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
        except Exception as e:
            print(f"Warning: Failed to restore snapshot: {e}")
        
        # Start VM
        start_cmd = [
            "VBoxManage", "startvm", self.vm_name,
            "--type", "headless"
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *start_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError(f"VirtualBox start failed: {stderr.decode()}")
            
            # Wait for VM to boot
            await asyncio.sleep(30)
            
            self.state = SandboxState.RUNNING
            return True
            
        except FileNotFoundError:
            raise RuntimeError("VirtualBox not found. Install VirtualBox")
    
    async def _start_docker(self) -> bool:
        """Start Docker container (limited Windows support)"""
        # Pull Windows container image
        pull_cmd = ["docker", "pull", "mcr.microsoft.com/windows:ltsc2022"]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *pull_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
        except:
            pass
        
        # Start container
        run_cmd = [
            "docker", "run", "-d",
            "--name", self.vm_name,
            "--isolation", "process",
            "-v", f"{self.temp_dir}:/samples",
            "mcr.microsoft.com/windows:ltsc2022",
            "cmd", "/c", "ping -t localhost"
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *run_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            
            self.state = SandboxState.RUNNING
            return True
            
        except FileNotFoundError:
            raise RuntimeError("Docker not found")
    
    async def _start_mock(self) -> bool:
        """Start mock sandbox for testing"""
        await asyncio.sleep(1)
        self.state = SandboxState.RUNNING
        return True
    
    async def copy_file_to_sandbox(self, local_path: str, remote_path: str) -> bool:
        """Copy file into sandbox environment"""
        if self.state != SandboxState.RUNNING:
            raise RuntimeError("Sandbox not running")
        
        if self.sandbox_type == SandboxType.QEMU:
            # Use SSH/SCP
            scp_cmd = [
                "scp", "-o", "StrictHostKeyChecking=no",
                "-P", str(self.vm_port),
                local_path,
                f"{self.vm_user}@{self.vm_ip}:{remote_path}"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *scp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
            
        elif self.sandbox_type == SandboxType.VIRTUALBOX:
            # Use VBoxManage copyto
            copy_cmd = [
                "VBoxManage", "guestcontrol", self.vm_name,
                "copyto", local_path, remote_path,
                "--username", self.vm_user,
                "--password", self.vm_password
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *copy_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
            
        elif self.sandbox_type == SandboxType.DOCKER:
            # Docker cp
            container_path = f"{self.vm_name}:{remote_path}"
            copy_cmd = ["docker", "cp", local_path, container_path]
            
            proc = await asyncio.create_subprocess_exec(
                *copy_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            return proc.returncode == 0
            
        elif self.sandbox_type == SandboxType.MOCK:
            # Just copy to temp dir
            shutil.copy(local_path, os.path.join(self.temp_dir, os.path.basename(local_path)))
            return True
        
        return False
    
    async def start_monitoring(self) -> bool:
        """Start monitoring agent in sandbox"""
        if self.state != SandboxState.RUNNING:
            raise RuntimeError("Sandbox not running")
        
        # Start the monitoring agent (vm_agent)
        if self.sandbox_type in [SandboxType.QEMU, SandboxType.VIRTUALBOX]:
            # Execute monitoring agent via SSH/guest control
            start_agent_cmd = "C:\\Monitoring\\start_agent.bat"
            await self._execute_command(start_agent_cmd)
        
        return True
    
    async def execute_file(
        self, 
        file_path: str, 
        timeout: int = 120,
        arguments: List[str] = None
    ) -> Dict[str, Any]:
        """Execute file in sandbox"""
        if self.state != SandboxState.RUNNING:
            raise RuntimeError("Sandbox not running")
        
        self.state = SandboxState.EXECUTING
        
        execution_result = {
            "file": file_path,
            "started": datetime.utcnow().isoformat(),
            "timeout": timeout,
            "status": "unknown",
            "exit_code": None
        }
        
        try:
            # Build command
            cmd = file_path
            if arguments:
                cmd += " " + " ".join(arguments)
            
            # Execute
            result = await asyncio.wait_for(
                self._execute_command(cmd),
                timeout=timeout
            )
            
            execution_result["status"] = "completed"
            execution_result["exit_code"] = result.get("exit_code", 0)
            
        except asyncio.TimeoutError:
            execution_result["status"] = "timeout"
            
        except Exception as e:
            execution_result["status"] = "error"
            execution_result["error"] = str(e)
        
        execution_result["ended"] = datetime.utcnow().isoformat()
        self.state = SandboxState.RUNNING
        
        return execution_result
    
    async def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute command in sandbox"""
        result = {"exit_code": 0, "stdout": "", "stderr": ""}
        
        if self.sandbox_type == SandboxType.QEMU:
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(self.vm_port),
                f"{self.vm_user}@{self.vm_ip}",
                command
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            result["exit_code"] = proc.returncode
            result["stdout"] = stdout.decode()
            result["stderr"] = stderr.decode()
            
        elif self.sandbox_type == SandboxType.VIRTUALBOX:
            exec_cmd = [
                "VBoxManage", "guestcontrol", self.vm_name,
                "run", "--exe", "cmd.exe",
                "--username", self.vm_user,
                "--password", self.vm_password,
                "--", "/c", command
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            result["exit_code"] = proc.returncode
            result["stdout"] = stdout.decode()
            result["stderr"] = stderr.decode()
            
        elif self.sandbox_type == SandboxType.DOCKER:
            exec_cmd = [
                "docker", "exec", self.vm_name,
                "cmd", "/c", command
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            result["exit_code"] = proc.returncode
            result["stdout"] = stdout.decode()
            result["stderr"] = stderr.decode()
            
        elif self.sandbox_type == SandboxType.MOCK:
            # Mock execution
            result["stdout"] = "Mock execution completed"
        
        return result
    
    async def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and collect results"""
        behavior_data = {
            "file_operations": [],
            "registry_operations": [],
            "process_operations": [],
            "network_operations": []
        }
        
        if self.sandbox_type == SandboxType.MOCK:
            # Return simulated data
            return self._generate_mock_behavior_data()
        
        # Retrieve monitoring logs from agent
        log_path = "C:\\Monitoring\\behavior_log.json"
        
        try:
            result = await self._execute_command(f"type {log_path}")
            if result["stdout"]:
                behavior_data = json.loads(result["stdout"])
        except:
            pass
        
        return behavior_data
    
    def _generate_mock_behavior_data(self) -> Dict[str, Any]:
        """Generate mock behavior data for testing"""
        return {
            "file_operations": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "operation": "encrypt",
                    "path": "C:\\Users\\test\\Documents\\file.docx",
                    "details": {"new_extension": ".locked"}
                }
            ],
            "registry_operations": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "operation": "set",
                    "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value_name": "Malware",
                    "value_data": "C:\\malware.exe"
                }
            ],
            "process_operations": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "operation": "create",
                    "process_name": "vssadmin.exe",
                    "process_id": 1234,
                    "parent_id": 5678,
                    "command_line": "vssadmin delete shadows /all /quiet"
                }
            ],
            "network_operations": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "operation": "http",
                    "destination": "185.100.85.100",
                    "port": 443,
                    "protocol": "https",
                    "data": {"method": "POST", "path": "/key_exchange"}
                }
            ]
        }
    
    async def cleanup(self):
        """Cleanup sandbox resources"""
        self.state = SandboxState.STOPPING
        
        try:
            if self.sandbox_type == SandboxType.QEMU:
                if self.process:
                    self.process.terminate()
                    await asyncio.sleep(5)
                    if self.process.poll() is None:
                        self.process.kill()
                        
            elif self.sandbox_type == SandboxType.VIRTUALBOX:
                stop_cmd = [
                    "VBoxManage", "controlvm", self.vm_name, "poweroff"
                ]
                proc = await asyncio.create_subprocess_exec(
                    *stop_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.wait()
                
            elif self.sandbox_type == SandboxType.DOCKER:
                stop_cmd = ["docker", "rm", "-f", self.vm_name]
                proc = await asyncio.create_subprocess_exec(
                    *stop_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.wait()
            
            # Cleanup temp directory
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                
        except Exception as e:
            print(f"Cleanup error: {e}")
        
        self.state = SandboxState.STOPPED
    
    async def take_snapshot(self, snapshot_name: str) -> bool:
        """Take VM snapshot"""
        if self.sandbox_type == SandboxType.QEMU:
            cmd = [
                "qemu-img", "snapshot", "-c", snapshot_name, self.vm_disk
            ]
        elif self.sandbox_type == SandboxType.VIRTUALBOX:
            cmd = [
                "VBoxManage", "snapshot", self.vm_name,
                "take", snapshot_name
            ]
        else:
            return False
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()
        
        return proc.returncode == 0
    
    def get_status(self) -> Dict[str, Any]:
        """Get sandbox status"""
        return {
            "type": self.sandbox_type.value,
            "state": self.state.value,
            "vm_name": self.vm_name,
            "snapshot": self.snapshot_name
        }


# Utility functions
async def create_sandbox(
    sandbox_type: str = "mock"
) -> SandboxController:
    """Create and start a sandbox"""
    controller = SandboxController(
        sandbox_type=SandboxType(sandbox_type)
    )
    await controller.start()
    return controller


if __name__ == "__main__":
    async def test():
        print("Testing sandbox controller...")
        
        # Test mock sandbox
        sandbox = SandboxController(sandbox_type=SandboxType.MOCK)
        
        print("Starting sandbox...")
        await sandbox.start()
        print(f"Status: {sandbox.get_status()}")
        
        print("Starting monitoring...")
        await sandbox.start_monitoring()
        
        print("Executing file...")
        result = await sandbox.execute_file("C:\\test.exe", timeout=10)
        print(f"Execution result: {result}")
        
        print("Collecting behavior data...")
        data = await sandbox.stop_monitoring()
        print(f"Behavior data: {json.dumps(data, indent=2)}")
        
        print("Cleaning up...")
        await sandbox.cleanup()
        print("Done!")
    
    asyncio.run(test())
