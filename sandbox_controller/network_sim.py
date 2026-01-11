"""
Network Simulation for Sandbox
Provides fake internet services (INetSim-like functionality)
"""

import os
import asyncio
import socket
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
import threading
import http.server
import socketserver
import ssl


@dataclass
class NetworkRequest:
    """Represents a captured network request"""
    timestamp: str
    protocol: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    data: Dict[str, Any] = field(default_factory=dict)


class FakeDNSServer:
    """
    Fake DNS server that resolves all queries to the sandbox IP
    """
    
    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 53):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.queries: List[NetworkRequest] = []
        self.response_ip = "192.168.100.1"  # All queries resolve to this
    
    def start(self):
        """Start DNS server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.listen_ip, self.listen_port))
        self.running = True
        
        thread = threading.Thread(target=self._serve)
        thread.daemon = True
        thread.start()
    
    def stop(self):
        """Stop DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def _serve(self):
        """Handle DNS queries"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)
                self._handle_query(data, addr)
            except:
                if self.running:
                    continue
                break
    
    def _handle_query(self, data: bytes, addr: tuple):
        """Handle a single DNS query"""
        try:
            # Parse query (simplified)
            domain = self._extract_domain(data)
            
            # Log query
            self.queries.append(NetworkRequest(
                timestamp=datetime.utcnow().isoformat(),
                protocol="dns",
                source_ip=addr[0],
                source_port=addr[1],
                destination_ip=self.listen_ip,
                destination_port=self.listen_port,
                data={"domain": domain}
            ))
            
            # Build response
            response = self._build_response(data)
            self.socket.sendto(response, addr)
            
        except Exception as e:
            print(f"DNS error: {e}")
    
    def _extract_domain(self, data: bytes) -> str:
        """Extract domain name from DNS query"""
        try:
            # Skip header (12 bytes)
            idx = 12
            labels = []
            
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    break
                idx += 1
                labels.append(data[idx:idx + length].decode('utf-8', errors='ignore'))
                idx += length
            
            return '.'.join(labels)
        except:
            return "unknown"
    
    def _build_response(self, query: bytes) -> bytes:
        """Build DNS response pointing to our IP"""
        # Transaction ID
        response = query[:2]
        
        # Flags: Standard response, no error
        response += b'\x81\x80'
        
        # Questions: 1, Answers: 1, Authority: 0, Additional: 0
        response += b'\x00\x01\x00\x01\x00\x00\x00\x00'
        
        # Copy question section
        idx = 12
        while query[idx] != 0:
            idx += query[idx] + 1
        idx += 5  # Null byte + QTYPE + QCLASS
        response += query[12:idx]
        
        # Answer section
        response += b'\xc0\x0c'  # Name pointer to question
        response += b'\x00\x01'  # Type A
        response += b'\x00\x01'  # Class IN
        response += b'\x00\x00\x00\x3c'  # TTL 60
        response += b'\x00\x04'  # Data length 4
        
        # IP address
        ip_parts = [int(p) for p in self.response_ip.split('.')]
        response += bytes(ip_parts)
        
        return response
    
    def get_queries(self) -> List[Dict]:
        """Get logged queries"""
        return [
            {
                "timestamp": q.timestamp,
                "source": f"{q.source_ip}:{q.source_port}",
                "domain": q.data.get("domain", "")
            }
            for q in self.queries
        ]


class FakeHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for fake HTTP server"""
    
    # Class variable to store requests
    requests = []
    
    def do_GET(self):
        """Handle GET request"""
        self._log_request("GET")
        
        # Return fake response based on path
        if ".exe" in self.path or ".dll" in self.path:
            self._send_fake_binary()
        elif ".txt" in self.path or ".html" in self.path:
            self._send_fake_text()
        else:
            self._send_default_response()
    
    def do_POST(self):
        """Handle POST request"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''
        
        self._log_request("POST", post_data)
        self._send_default_response()
    
    def _log_request(self, method: str, body: bytes = None):
        """Log request"""
        FakeHTTPHandler.requests.append({
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "client": self.client_address,
            "body_size": len(body) if body else 0
        })
    
    def _send_fake_binary(self):
        """Send fake binary file"""
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        # Send minimal PE header
        self.wfile.write(b'MZ' + b'\x00' * 100)
    
    def _send_fake_text(self):
        """Send fake text response"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>OK</body></html>")
    
    def _send_default_response(self):
        """Send default response"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class FakeHTTPServer:
    """
    Fake HTTP server for capturing malware C2 traffic
    """
    
    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 80):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.server: Optional[socketserver.TCPServer] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start HTTP server"""
        FakeHTTPHandler.requests = []  # Clear previous requests
        
        self.server = socketserver.TCPServer(
            (self.listen_ip, self.listen_port),
            FakeHTTPHandler
        )
        self.server.allow_reuse_address = True
        
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop HTTP server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
    
    def get_requests(self) -> List[Dict]:
        """Get captured requests"""
        return FakeHTTPHandler.requests.copy()


class FakeHTTPSServer(FakeHTTPServer):
    """
    Fake HTTPS server with self-signed certificate
    """
    
    def __init__(
        self, 
        listen_ip: str = "0.0.0.0", 
        listen_port: int = 443,
        cert_file: str = None,
        key_file: str = None
    ):
        super().__init__(listen_ip, listen_port)
        self.cert_file = cert_file or self._generate_self_signed_cert()
        self.key_file = key_file or self.cert_file
    
    def _generate_self_signed_cert(self) -> str:
        """Generate self-signed certificate"""
        import tempfile
        
        cert_path = os.path.join(tempfile.gettempdir(), "sandbox_cert.pem")
        
        # Generate using openssl if available
        try:
            import subprocess
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", cert_path, "-out", cert_path,
                "-days", "365", "-nodes",
                "-subj", "/CN=sandbox.local"
            ], check=True, capture_output=True)
        except:
            # Create minimal cert file
            with open(cert_path, 'w') as f:
                f.write("# Placeholder - generate real cert")
        
        return cert_path
    
    def start(self):
        """Start HTTPS server"""
        FakeHTTPHandler.requests = []
        
        self.server = socketserver.TCPServer(
            (self.listen_ip, self.listen_port),
            FakeHTTPHandler
        )
        self.server.allow_reuse_address = True
        
        # Wrap with SSL
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert_file, self.key_file)
            self.server.socket = context.wrap_socket(
                self.server.socket,
                server_side=True
            )
        except Exception as e:
            print(f"SSL setup failed: {e}")
        
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()


class NetworkSimulator:
    """
    Main network simulator that coordinates all fake services
    """
    
    def __init__(self, listen_ip: str = "192.168.100.1"):
        self.listen_ip = listen_ip
        
        self.dns_server = FakeDNSServer(listen_ip, 53)
        self.http_server = FakeHTTPServer(listen_ip, 80)
        self.https_server = FakeHTTPSServer(listen_ip, 443)
        
        self.running = False
    
    def start(self):
        """Start all fake services"""
        print(f"Starting network simulator on {self.listen_ip}")
        
        try:
            self.dns_server.start()
            print("  - DNS server started (port 53)")
        except Exception as e:
            print(f"  - DNS server failed: {e}")
        
        try:
            self.http_server.start()
            print("  - HTTP server started (port 80)")
        except Exception as e:
            print(f"  - HTTP server failed: {e}")
        
        try:
            self.https_server.start()
            print("  - HTTPS server started (port 443)")
        except Exception as e:
            print(f"  - HTTPS server failed: {e}")
        
        self.running = True
    
    def stop(self):
        """Stop all services"""
        self.dns_server.stop()
        self.http_server.stop()
        self.https_server.stop()
        self.running = False
    
    def get_traffic_log(self) -> Dict[str, List]:
        """Get all captured traffic"""
        return {
            "dns_queries": self.dns_server.get_queries(),
            "http_requests": self.http_server.get_requests(),
            "https_requests": self.https_server.get_requests()
        }


if __name__ == "__main__":
    print("Starting network simulator...")
    
    simulator = NetworkSimulator("127.0.0.1")
    
    try:
        simulator.start()
        print("\nNetwork simulator running. Press Ctrl+C to stop.")
        
        while True:
            import time
            time.sleep(10)
            
            traffic = simulator.get_traffic_log()
            if any(traffic.values()):
                print(f"\nCaptured traffic: {json.dumps(traffic, indent=2)}")
                
    except KeyboardInterrupt:
        print("\nStopping...")
        simulator.stop()
