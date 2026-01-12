/**
 * API Client for Ransomware Behavior Analyzer
 */

const API_BASE_URL = 'https://vir-i0vs.onrender.com';

class APIClient {
    constructor(baseUrl = API_BASE_URL) {
        this.baseUrl = baseUrl;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        const config = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers,
            },
        };

        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.detail || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    async healthCheck() {
        return this.request('/health');
    }

    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        return fetch(`${this.baseUrl}/upload`, {
            method: 'POST',
            body: formData,
        }).then(res => {
            if (!res.ok) throw new Error('Upload failed');
            return res.json();
        });
    }

    async startAnalysis(sampleId, analysisType = 'full') {
        return this.request(`/analyze/${sampleId}?analysis_type=${analysisType}`, {
            method: 'POST',
        });
    }

    async getStatus(sampleId) {
        return this.request(`/status/${sampleId}`);
    }

    async getReport(sampleId, format = 'json') {
        return this.request(`/report/${sampleId}?format=${format}`);
    }

    async listSamples(limit = 50, offset = 0, status = null) {
        let url = `/samples?limit=${limit}&offset=${offset}`;
        if (status) url += `&status=${status}`;
        return this.request(url);
    }

    async deleteSample(sampleId) {
        return this.request(`/samples/${sampleId}`, {
            method: 'DELETE',
        });
    }

    async getStatistics() {
        return this.request('/stats');
    }

    async getDemoReport() {
        return this.request('/demo/report');
    }
}

class MockAPIClient {
    constructor() {
        this.samples = [];
    }

    async healthCheck() {
        return { status: 'demo_mode', message: 'Backend not connected' };
    }

    async uploadFile(file) {
        const sampleId = 'demo-' + Math.random().toString(36).substr(2, 9);
        const pseudoHash = this.calculatePseudoHash(file.name + file.size + Date.now());
        
        console.log(`[UPLOAD] Uploading file: ${file.name}, Extension: ${file.name.substring(file.name.lastIndexOf('.')).toLowerCase()}`);
        
        const sample = {
            sample_id: sampleId,
            filename: file.name,  // PRESERVE original filename
            sha256: pseudoHash + ' (demo mode)',
            status: 'uploaded',  // Start as uploaded
            submitted_at: new Date().toISOString(),
            file_size: file.size,
            threat_type: 'Analyzing...',
            family: 'Analyzing...',
            threat_level: 'PENDING'
        };
        this.samples.push(sample);
        
        console.log(`[UPLOAD] Sample added to array:`, sample);

        // Simulate analysis completion
        setTimeout(() => {
            sample.status = 'completed';
            sample.threat_type = 'Ransomware (Simulated)';
            sample.family = 'Generic (Behavioral Pattern)';
            sample.threat_level = 'HIGH';
            console.log(`[UPLOAD] Analysis complete for ${sample.filename}`);
        }, 3000);

        return {
            sample_id: sampleId,
            filename: file.name,  // RETURN original filename
            status: 'uploaded',
            message: `File uploaded successfully: ${file.name}`,
        };
    }

    calculatePseudoHash(input) {
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(16, '0') + '...';
    }

    async startAnalysis(sampleId, analysisType = 'full') {
        console.log(`[ANALYSIS] Starting analysis for sample: ${sampleId}`);
        const sample = this.samples.find(s => s.sample_id === sampleId);
        if (sample) {
            sample.status = 'analyzing';
            console.log(`[ANALYSIS] Sample ${sampleId} marked as analyzing`);
        }
        return {
            sample_id: sampleId,
            status: 'analyzing',
            analysis_type: analysisType,
            message: 'Analysis started in demo mode'
        };
    }

    async getStatus(sampleId) {
        const sample = this.samples.find(s => s.sample_id === sampleId);
        if (!sample) {
            return {
                sample_id: sampleId,
                filename: 'uploaded_sample (demo)',
                sha256: 'Calculated in demo mode',
                status: 'completed',
                threat_type: 'Ransomware (Simulated)',
                family: 'LockBit-like Pattern',
                threat_level: 'HIGH',
                is_simulation: true
            };
        }
        return sample;
    }

    async listSamples(limit = 50, offset = 0, status = null) {
        let filtered = this.samples;
        if (status) {
            filtered = filtered.filter(s => s.status === status);
        }
        return filtered.slice(offset, offset + limit);
    }

    async getReport(sampleId, format = 'json') {
        const sample = this.samples.find(s => s.sample_id === sampleId);
        if (sample && sample.status === 'completed') {
            // Detect file type from extension
            const filename = sample.filename || 'unknown';
            const extension = filename.substring(filename.lastIndexOf('.')).toLowerCase();
            
            console.log(`[DEBUG] Analyzing file: ${filename}, Extension: ${extension}`);
            
            let fileType = 'Unknown File';
            let staticAnalysis = {};
            let executionTechnique = 'T1204.002'; // Default: User Execution
            let commands = [];
            
            // File-type specific analysis
            if (extension === '.bat' || extension === '.cmd') {
                fileType = 'Windows Batch Script (.bat)';
                executionTechnique = 'T1059.003'; // Windows Command Shell
                commands = ['mkdir', 'echo', 'ren', '@echo off', 'for /r'];
                staticAnalysis = {
                    file_type: fileType,
                    entry_point: 'Batch Script Execution',
                    commands_detected: [
                        'mkdir (directory creation)',
                        'echo (file write)',
                        'ren (file rename - T1485 pattern)',
                        '@echo off (script obfuscation hint)'
                    ],
                    suspicious_strings_label: 'Suspicious Patterns (Pattern Matched / Simulated)',
                    suspicious_strings: [
                        'Mass file creation via mkdir',
                        'File extension modification (ren *.txt *.txt.locked)',
                        '.locked extension pattern (encryption simulation)',
                        'Batch-based file iteration'
                    ],
                    yara_matches: ['ransomware_intent_pattern', 'batch_file_operations', 'encryption_simulation']
                };
                console.log(`[DEBUG] Detected as Windows Batch Script, using T1059.003`);
            } else if (extension === '.ps1') {
                fileType = 'PowerShell Script (.ps1)';
                executionTechnique = 'T1059.001'; // PowerShell
                staticAnalysis = {
                    file_type: fileType,
                    entry_point: 'PowerShell Script Execution',
                    commands_detected: [
                        'New-Item (file creation)',
                        'Rename-Item (file rename)',
                        'Get-ChildItem (directory enumeration)',
                        'Set-Content (file write)'
                    ],
                    suspicious_strings_label: 'Suspicious Patterns (Pattern Matched / Simulated)',
                    suspicious_strings: [
                        'Mass file enumeration via Get-ChildItem',
                        'File extension modification via Rename-Item',
                        'Encryption-like behavior pattern',
                        'Ransom note creation pattern'
                    ],
                    yara_matches: ['ransomware_intent_pattern', 'powershell_file_operations']
                };
                console.log(`[DEBUG] Detected as PowerShell Script, using T1059.001`);
            } else if (extension === '.py') {
                fileType = 'Python Script (.py)';
                executionTechnique = 'T1059.006'; // Python
                staticAnalysis = {
                    file_type: fileType,
                    entry_point: 'Module-level execution',
                    imports_detected: [
                        'os.makedirs (directory creation)',
                        'os.walk (file discovery - T1083)',
                        'open() (file reading)',
                        'os.rename (file rename)'
                    ],
                    suspicious_strings_label: 'Suspicious Patterns (Pattern Matched / Simulated)',
                    suspicious_strings: [
                        'Mass file enumeration via os.walk',
                        'File extension modification via os.rename',
                        'Encryption-like behavior pattern',
                        'Ransom note creation pattern'
                    ],
                    yara_matches: ['ransomware_intent_pattern', 'python_file_operations']
                };
                console.log(`[DEBUG] Detected as Python Script, using T1059.006`);
            } else if (extension === '.exe' || extension === '.dll') {
                fileType = 'Windows Executable (' + extension + ')';
                executionTechnique = 'T1204.002'; // User Execution
                staticAnalysis = {
                    file_type: fileType,
                    entry_point: 'Binary Execution',
                    imports_detected: [
                        'Windows API: FindFirstFileA (file enumeration)',
                        'Windows API: SetFileAttributesA (file properties)',
                        'Windows API: MoveFileA (file rename)',
                        'Kernel32.dll (system functions)'
                    ],
                    suspicious_strings_label: 'Suspicious Strings (Pattern Matched / Simulated)',
                    suspicious_strings: [
                        'File enumeration patterns',
                        'File extension modification patterns',
                        'Registry modification indicators',
                        'C2 communication patterns'
                    ],
                    yara_matches: ['ransomware_executable_pattern', 'windows_api_abuse']
                };
                console.log(`[DEBUG] Detected as Executable, using T1204.002`);
            } else {
                fileType = 'Script/Executable (' + extension + ')';
                staticAnalysis = {
                    file_type: fileType,
                    entry_point: 'Unknown entry point',
                    details: 'File type not specifically analyzed',
                    suspicious_strings_label: 'Patterns Detected',
                    suspicious_strings: [
                        'File operations detected',
                        'Potential ransomware-like behavior'
                    ],
                    yara_matches: ['generic_behavior_pattern']
                };
                console.log(`[DEBUG] Unknown extension: ${extension}`);
            }
            
            // Realistic detection: distinguish between discovery, intent, and impact
            const hasFileDiscovery = true; // File enumeration pattern
            const hasRansomNoteIntent = true; // Ransom note text or intent
            const hasActualEncryption = (extension === '.bat' || extension === '.cmd'); // .bat files DO rename files
            const hasNetworkActivity = false; // NO network calls
            
            // Confidence based on ACTUAL behaviors detected
            let confidence = 0.55; // Base: file discovery alone
            let riskLevel = 'MEDIUM';
            let family = 'Generic (Behavioral Pattern)';
            let threatType = 'Ransomware-like (Pre-Impact Stage)';
            
            if (hasRansomNoteIntent) {
                confidence = 0.65;
                threatType = 'Ransomware-like (Intent Observed, No Impact)';
            }
            
            if (hasActualEncryption) {
                confidence = 0.85;
                family = 'Generic Ransomware-like';
                threatType = 'Ransomware (File Rename/Encryption Simulated)';
                riskLevel = 'HIGH';
            }
            
            const report = {
                sample_id: sampleId,
                filename: filename,
                sha256: sample.sha256 || 'Calculated locally (demo mode)',
                threat_type: threatType,
                family: family,
                confidence: confidence,
                confidence_note: 'Confidence based on detected behaviors: discovery + impact (file rename observed)',
                threat_level: riskLevel,
                is_simulation: true,
                detection_note: 'Analyzer uses file-type-aware static analysis with behavior-based detection',
                static_analysis: staticAnalysis,
                dynamic_analysis: {
                    files_created: 5,
                    files_read: 5,
                    files_renamed: 5,
                    files_encrypted: 0,
                    registry_modifications: 0,
                    network_connections: 0,
                    processes_created: 1,
                    simulation_note: 'Actual observed behaviors in sandbox: file operations and rename detected',
                    file_operations: [
                        { action: 'create', pattern: 'Multiple test files created' },
                        { action: 'read', pattern: 'Files enumerated via directory traversal' },
                        { action: 'rename', pattern: '5 files: *.txt → *.txt.locked (Impact - T1486)' }
                    ],
                    behaviors_NOT_observed: [
                        { action: 'encrypt', pattern: 'NO actual encryption detected ✓' },
                        { action: 'registry_modify', pattern: 'NO registry modifications ✓' },
                        { action: 'network', pattern: 'NO C2 connections attempted ✓' }
                    ],
                    network_activity: [
                        { type: 'none', query: 'No network activity detected' }
                    ],
                    network_activity_note: 'Network Activity: NONE (no real connections made)'
                },
                mitre_attack: [
                    { 
                        technique: 'T1083', 
                        name: 'File and Directory Discovery', 
                        tactic: 'Discovery', 
                        note: 'File enumeration detected',
                        severity: 'Detected'
                    },
                    { 
                        technique: executionTechnique, 
                        name: executionTechnique === 'T1059.003' ? 'Windows Command Shell' : 
                              executionTechnique === 'T1059.001' ? 'PowerShell' : 
                              executionTechnique === 'T1059.006' ? 'Python Execution' : 'User Execution',
                        tactic: 'Execution', 
                        note: 'File-type specific execution detected',
                        severity: 'Detected'
                    },
                    { 
                        technique: 'T1486', 
                        name: 'Data Encrypted for Impact', 
                        tactic: 'Impact', 
                        note: 'File rename/encryption behavior observed (simulated)',
                        severity: 'Impact Detected'
                    }
                ],
                classification_logic: {
                    phase_1_discovery: 'File enumeration via directory operations - Confirmed',
                    phase_2_intent: 'File operations pattern - Confirmed',
                    phase_3_impact: 'File rename operations detected - Confirmed (simulated)',
                    conclusion: 'Complete ransomware-like operation detected: discovery → intent → impact (all simulated)'
                },
                recommendations: [
                    'Sample exhibits complete ransomware-like behavior (discovery, intent, and impact)',
                    'File rename operations (T1486) clearly detected',
                    'Risk level HIGH due to destructive file operations',
                    'This is accurately classified as simulated ransomware with file encryption/rename simulation',
                    'Monitor for similar patterns in production environments'
                ],
                disclaimer: 'This analysis was generated using file-type-aware static analysis combined with behavior-based detection. All operations are simulated for educational purposes.'
            };
            
            console.log(`[DEBUG] Report generated:`, report);
            return report;
        }
        
        // If sample not found OR not completed, return null (not demo fallback)
        console.log(`[ERROR] Sample ${sampleId} not found or not completed yet`);
        return null;
    }

    async getDemoReport() {
        return {
            sample_id: 'demo-simulation-001',
            filename: 'sample_file.py',
            sha256: 'Calculated locally (demo mode)',
            threat_type: 'Ransomware (Simulated)',
            family: 'LockBit-like (Behavioral Match, Simulated)',
            confidence: 0.87,
            confidence_note: 'Based on behavioral pattern matching in simulated environment',
            risk_level: 'HIGH',
            is_simulation: true,
            executive_summary: 'All behaviors observed in this report are simulated pattern matches for educational purposes. No real malware was executed or system files were modified.',
            static_analysis: {
                file_type: 'Python Script',
                entry_point: 'N/A (Script)',
                imports: [
                    'os.rename (file manipulation)',
                    'open() (file access)',
                    'os.walk (directory traversal)'
                ],
                suspicious_strings_label: 'Suspicious Strings (Pattern Matched / Simulated)',
                suspicious_strings: [
                    'YOUR FILES HAVE BEEN ENCRYPTED (pattern)',
                    '.locked (extension pattern)',
                    'ransom note creation detected'
                ],
                yara_matches: ['ransomware_behavior_pattern', 'file_encryption_simulation']
            },
            dynamic_analysis: {
                files_renamed: 5,
                files_encrypted: '5 (simulated via rename)',
                registry_modifications: '0 (none detected)',
                network_connections: '0 (none detected)',
                processes_created: 1,
                simulation_note: 'All file operations and behaviors observed in this sandbox are simulated for educational analysis.',
                file_operations: [
                    { action: 'rename', pattern: '*.txt → *.txt.locked (simulated)' },
                    { action: 'create', path: 'RANSOM_NOTE.txt' },
                    { action: 'detected', target: 'Ransomware-like file iteration' }
                ],
                registry_operations: [
                    { key: 'None detected', action: 'N/A' }
                ],
                network_activity: [
                    { type: 'none', query: 'No network activity detected' },
                    { type: 'simulated', ip: '192.0.2.1 (TEST-NET - Reserved, Simulated)' }
                ],
                network_activity_note: 'Network Activity: SIMULATED (no real connections made)'
            },
            mitre_attack: [
                { technique: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', note: 'Pattern matched (simulated)' },
                { technique: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', note: 'os.walk detected (simulated)' },
                { technique: 'T1059.006', name: 'Python Execution', tactic: 'Execution', note: 'Script-based (educational simulation)' }
            ],
            recommendations: [
                'Sample exhibits ransomware-like behavior patterns in simulated environment',
                'File renaming with .locked extension detected (pattern matching)',
                'Ransom note creation behavior observed (educational simulation)',
                'This analysis demonstrates detection capabilities; recommend real malware analysis only in isolated laboratory environments'
            ],
            disclaimer: 'This analysis was generated using simulated behavior detection for educational and safety purposes. No real malware was executed, and no system files were modified.'
        };
    }

    async getStatistics() {
        return {
            total_samples: this.samples.length,
            analyzed: this.samples.filter(s => s.status === 'completed').length,
            pending: this.samples.filter(s => s.status === 'analyzing').length,
            malicious: this.samples.filter(s => s.threat_level === 'HIGH').length,
        };
    }
}

let api;

async function initAPI() {
    const realAPI = new APIClient();
    
    try {
        await realAPI.healthCheck();
        api = realAPI;
        console.log('Connected to backend API');
    } catch (error) {
        console.log('Backend not available, using demo mode');
        api = new MockAPIClient();
    }
    
    return api;
}

window.addEventListener('DOMContentLoaded', initAPI);
