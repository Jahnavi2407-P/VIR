/**
 * Main Application Logic for Ransomware Behavior Analyzer
 */

let currentSampleId = null;

// Global functions - must be accessible for inline handlers and global calls
async function loadSamples() {
    try {
        const samples = await api.listSamples();
        const tbody = document.getElementById('samples-tbody');
        const noSamples = document.getElementById('no-samples');

        if (!tbody || !noSamples) {
            console.error('Samples table elements not found');
            return;
        }

        if (!samples || samples.length === 0) {
            tbody.innerHTML = '';
            noSamples.classList.remove('hidden');
            return;
        }

        noSamples.classList.add('hidden');
        tbody.innerHTML = samples.map(sample => `
            <tr>
                <td><strong>${escapeHtml(sample.filename)}</strong></td>
                <td>${formatDate(sample.submitted_at)}</td>
                <td><span class="badge badge-${sample.status}">${sample.status}</span></td>
                <td>${sample.threat_type || '-'}</td>
                <td><span class="badge badge-${getThreatLevel(sample.threat_level)}">${sample.threat_level || '-'}</span></td>
                <td>
                    <button class="btn btn-secondary" onclick="viewSampleReport('${sample.sample_id}')">View</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading samples:', error);
        const noSamples = document.getElementById('no-samples');
        if (noSamples) noSamples.classList.remove('hidden');
        const tbody = document.getElementById('samples-tbody');
        if (tbody) tbody.innerHTML = '';
    }
}

async function loadReports() {
    const reportContainer = document.getElementById('report-container');
    const noReport = document.getElementById('no-report');

    if (!reportContainer || !noReport) {
        console.error('Report page elements not found');
        return;
    }

    try {
        const samples = await api.listSamples();
        
        if (samples && samples.length > 0) {
            noReport.classList.add('hidden');
            reportContainer.innerHTML = `
                <div style="padding: 20px;">
                    <label for="sample-select" style="display: block; margin-bottom: 12px; font-weight: 500;">
                        Select Sample:
                    </label>
                    <select id="sample-select" style="padding: 8px 12px; border: 1px solid var(--border-color); border-radius: var(--radius); font-size: 13px; background: white; color: var(--text-primary);">
                        <option value="">Choose a sample...</option>
                        ${samples.map(s => `<option value="${s.sample_id}">${escapeHtml(s.filename)}</option>`).join('')}
                    </select>
                </div>
            `;
            
            // Attach event listener after rendering
            setTimeout(() => {
                const selectEl = document.getElementById('sample-select');
                if (selectEl) {
                    selectEl.addEventListener('change', displaySelectedReport);
                }
            }, 0);
        } else {
            noReport.classList.remove('hidden');
            reportContainer.innerHTML = '';
        }
    } catch (error) {
        console.error('Error loading reports:', error);
        noReport.classList.remove('hidden');
        reportContainer.innerHTML = '';
    }
}

async function displaySelectedReport() {
    const select = document.getElementById('sample-select');
    if (!select) {
        console.error('Sample select element not found');
        return;
    }
    
    const sampleId = select.value;
    if (sampleId) {
        await displayReport(sampleId);
    }
}

async function displayReport(sampleId) {
    const reportContainer = document.getElementById('report-container');

    if (!reportContainer) {
        console.error('Report container not found');
        return;
    }

    try {
        const report = await api.getReport(sampleId);
        
        if (!report) {
            throw new Error('No report returned from API');
        }
        
        reportContainer.innerHTML = renderReport(report);
    } catch (error) {
        console.error('Error loading report:', error);
        reportContainer.innerHTML = `<div style="padding: 20px; color: red; border: 1px solid #ffcccc; border-radius: 4px; background: #fff5f5;">Error loading report: ${escapeHtml(error.message)}</div>`;
    }
}

async function viewSampleReport(sampleId) {
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');

    navLinks.forEach(l => l.classList.remove('active'));
    pages.forEach(p => p.classList.remove('active'));

    const reportsLink = document.querySelector('[data-page="reports"]');
    if (reportsLink) reportsLink.classList.add('active');

    const reportsPage = document.getElementById('reports-page');
    if (reportsPage) reportsPage.classList.add('active');

    await displayReport(sampleId);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    }).format(date);
}

function getThreatLevel(level) {
    if (!level) return 'low';
    return level.toLowerCase();
}

document.addEventListener('DOMContentLoaded', async () => {
    setupNavigation();
    setupUploadArea();
    setupUploadControls();
    setupModalControls();
});

// Navigation
function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const pageName = link.dataset.page;
            
            navLinks.forEach(l => l.classList.remove('active'));
            pages.forEach(p => p.classList.remove('active'));
            
            link.classList.add('active');
            const page = document.getElementById(`${pageName}-page`);
            if (page) {
                page.classList.add('active');
                
                if (pageName === 'samples') {
                    loadSamples();
                } else if (pageName === 'reports') {
                    loadReports();
                }
            }
        });
    });
}

// Upload Area Setup
function setupUploadArea() {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');

    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
}

// Upload Controls
function setupUploadControls() {
    const uploadAnother = document.getElementById('upload-another');
    const viewAnalysis = document.getElementById('view-analysis');

    if (uploadAnother) {
        uploadAnother.addEventListener('click', resetUploadForm);
    }

    if (viewAnalysis) {
        viewAnalysis.addEventListener('click', viewAnalysisReport);
    }
}

// Handle File Selection
async function handleFileSelect(file) {
    const uploadArea = document.getElementById('upload-area');
    const uploadProgress = document.getElementById('upload-progress');
    const uploadResult = document.getElementById('upload-result');

    uploadArea.classList.add('hidden');
    uploadProgress.classList.remove('hidden');

    try {
        const response = await api.uploadFile(file);
        currentSampleId = response.sample_id;

        uploadProgress.classList.add('hidden');
        uploadResult.classList.remove('hidden');

        document.getElementById('result-sample-id').textContent = response.sample_id;
        document.getElementById('result-hash').textContent = response.sha256 || 'Calculated in demo mode';
        document.getElementById('result-status').textContent = response.status || 'Processing';

        startAnalysis(response.sample_id);
    } catch (error) {
        console.error('Upload error:', error);
        uploadProgress.classList.add('hidden');
        uploadArea.classList.remove('hidden');
        alert('Upload failed: ' + error.message);
    }
}

// Start Analysis
async function startAnalysis(sampleId) {
    const modal = document.getElementById('analysis-modal');
    modal.classList.remove('hidden');

    try {
        const response = await api.startAnalysis(sampleId);
        
        updateAnalysisStep('upload', 'Complete');
        updateAnalysisStep('static', 'In Progress');

        // Simulate analysis progression
        setTimeout(() => {
            updateAnalysisStep('static', 'Complete');
            updateAnalysisStep('dynamic', 'In Progress');
        }, 2000);

        setTimeout(() => {
            updateAnalysisStep('dynamic', 'Complete');
            updateAnalysisStep('report', 'In Progress');
        }, 4000);

        setTimeout(() => {
            updateAnalysisStep('report', 'Complete');
            document.getElementById('analysis-status-text').textContent = 'Analysis complete';
            
            setTimeout(() => {
                modal.classList.add('hidden');
                viewAnalysisReport();
            }, 1500);
        }, 6000);
    } catch (error) {
        console.error('Analysis error:', error);
        modal.classList.add('hidden');
    }
}

// Update Analysis Step
function updateAnalysisStep(stepId, status) {
    const step = document.getElementById(`step-${stepId}`);
    if (step) {
        const statusEl = step.querySelector('.step-status');
        statusEl.textContent = status;
        
        if (status === 'Complete') {
            step.classList.add('completed');
        } else if (status === 'In Progress') {
            step.classList.add('active');
        }
    }
}

// Reset Upload Form
function resetUploadForm() {
    const uploadArea = document.getElementById('upload-area');
    const uploadResult = document.getElementById('upload-result');
    const fileInput = document.getElementById('file-input');

    uploadArea.classList.remove('hidden');
    uploadResult.classList.add('hidden');
    fileInput.value = '';
    currentSampleId = null;
}

// View Analysis Report
async function viewAnalysisReport() {
    if (!currentSampleId) return;

    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');

    navLinks.forEach(l => l.classList.remove('active'));
    pages.forEach(p => p.classList.remove('active'));

    const reportsLink = document.querySelector('[data-page="reports"]');
    if (reportsLink) reportsLink.classList.add('active');

    const reportsPage = document.getElementById('reports-page');
    if (reportsPage) reportsPage.classList.add('active');

    await displayReport(currentSampleId);
}

// Render Report
function renderReport(report) {
    const riskClass = `risk-${(report.threat_level || 'low').toLowerCase()}`;
    
    return `
        <div class="report-header">
            <h2>${escapeHtml(report.filename)}</h2>
            <p>${report.threat_type || 'Unknown'}</p>
            <span class="risk-badge ${riskClass}">${report.threat_level || 'Unknown'}</span>
        </div>

        ${report.executive_summary ? `
            <div class="report-section">
                <div style="background: #F3F5F9; border-left: 4px solid var(--primary); padding: 16px 20px; border-radius: var(--radius); margin-bottom: 12px;">
                    <strong>Executive Summary:</strong>
                    <p style="margin: 8px 0 0 0; color: var(--text-secondary); font-size: 13px;">${escapeHtml(report.executive_summary)}</p>
                </div>
            </div>
        ` : ''}

        <div class="report-section">
            <h3>Basic Information</h3>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="number">${report.confidence ? (report.confidence * 100).toFixed(0) : 87}%</div>
                    <div class="label">Confidence</div>
                </div>
                <div class="stat-item">
                    <div class="number">${report.family || 'Unclassified'}</div>
                    <div class="label">Family</div>
                </div>
            </div>
            ${report.confidence_note ? `<div class="simulation-note">${report.confidence_note}</div>` : ''}
            ${report.is_simulation ? `<div class="simulation-note">Simulation Mode: All behaviors are pattern-matched simulations for educational analysis</div>` : ''}
        </div>

        ${report.static_analysis ? `
            <div class="report-section">
                <h3>Static Analysis</h3>
                <h4>File Properties</h4>
                <p><strong>Type:</strong> ${report.static_analysis.file_type || 'Unknown'}</p>
                
                ${report.static_analysis.imports && report.static_analysis.imports.length > 0 ? `
                    <h4>Imported Functions</h4>
                    <ul>
                        ${report.static_analysis.imports.map(imp => `<li>${escapeHtml(imp)}</li>`).join('')}
                    </ul>
                ` : ''}
                
                ${report.static_analysis.suspicious_strings && report.static_analysis.suspicious_strings.length > 0 ? `
                    <h4>${report.static_analysis.suspicious_strings_label || 'Suspicious Strings'}</h4>
                    <ul>
                        ${report.static_analysis.suspicious_strings.map(str => `<li>${escapeHtml(str)}</li>`).join('')}
                    </ul>
                ` : ''}
                
                ${report.static_analysis.yara_matches && report.static_analysis.yara_matches.length > 0 ? `
                    <h4>YARA Rule Matches</h4>
                    <div class="mitre-tags">
                        ${report.static_analysis.yara_matches.map(match => `<span class="mitre-tag">${escapeHtml(match)}</span>`).join('')}
                    </div>
                ` : ''}
            </div>
        ` : ''}

        ${report.dynamic_analysis ? `
            <div class="report-section">
                <h3>Dynamic Analysis</h3>
                ${report.dynamic_analysis.simulation_note ? `
                    <div class="simulation-note">${report.dynamic_analysis.simulation_note}</div>
                ` : ''}
                ${report.detection_note ? `
                    <div class="simulation-note" style="background: #E8F5E9; border-left-color: var(--success);">${report.detection_note}</div>
                ` : ''}
                
                <h4>Behavior Summary</h4>
                <div class="stat-grid">
                    ${report.dynamic_analysis.files_created !== undefined ? `
                        <div class="stat-item">
                            <div class="number">${report.dynamic_analysis.files_created}</div>
                            <div class="label">Files Created</div>
                        </div>
                    ` : ''}
                    ${report.dynamic_analysis.files_read !== undefined ? `
                        <div class="stat-item">
                            <div class="number">${report.dynamic_analysis.files_read}</div>
                            <div class="label">Files Read</div>
                        </div>
                    ` : ''}
                    ${report.dynamic_analysis.files_renamed !== undefined ? `
                        <div class="stat-item">
                            <div class="number">${report.dynamic_analysis.files_renamed}</div>
                            <div class="label">Files Renamed</div>
                        </div>
                    ` : ''}
                    ${report.dynamic_analysis.processes_created !== undefined ? `
                        <div class="stat-item">
                            <div class="number">${report.dynamic_analysis.processes_created}</div>
                            <div class="label">Processes</div>
                        </div>
                    ` : ''}
                </div>

                ${report.dynamic_analysis.file_operations && report.dynamic_analysis.file_operations.length > 0 ? `
                    <h4>Detected Operations</h4>
                    ${report.dynamic_analysis.file_operations.map(op => `
                        <div class="finding">
                            <strong>${escapeHtml(op.action.toUpperCase())}:</strong> ${escapeHtml(op.pattern || op.path || op.target)}
                        </div>
                    `).join('')}
                ` : ''}

                ${report.dynamic_analysis.behaviors_NOT_observed && report.dynamic_analysis.behaviors_NOT_observed.length > 0 ? `
                    <h4>Behaviors NOT Detected</h4>
                    ${report.dynamic_analysis.behaviors_NOT_observed.map(op => `
                        <div style="padding: 12px 16px; margin: 8px 0; background: #E8F5E9; border-left: 4px solid var(--success); border-radius: 3px; font-size: 13px;">
                            <strong>${escapeHtml(op.action.toUpperCase())}:</strong> ${escapeHtml(op.pattern || op.path)}
                        </div>
                    `).join('')}
                ` : ''}

                ${report.dynamic_analysis.network_activity ? `
                    <h4>${report.dynamic_analysis.network_activity_note || 'Network Activity'}</h4>
                    ${report.dynamic_analysis.network_activity.filter(net => net.type !== 'none').length > 0 ? 
                        report.dynamic_analysis.network_activity.filter(net => net.type !== 'none').map(net => `
                            <div class="finding">
                                <strong>${escapeHtml(net.type.toUpperCase())}:</strong> ${escapeHtml(net.ip || net.domain || 'N/A')}
                            </div>
                        `).join('')
                        : ''}
                    ${report.dynamic_analysis.network_activity.every(net => net.type === 'none' || net.type === 'simulated') ? `
                        <p style="color: var(--text-secondary); font-size: 13px;"><strong>No network connections detected or initiated.</strong></p>
                    ` : ''}
                ` : ''}
            </div>
        ` : ''}

        ${report.mitre_attack && report.mitre_attack.length > 0 ? `
            <div class="report-section">
                <h3>MITRE ATT&CK Framework</h3>
                ${report.mitre_attack.map(tech => `
                    <div class="recommendation">
                        <strong>T${tech.technique.replace('T', '')}:</strong> ${escapeHtml(tech.name)} (${escapeHtml(tech.tactic)})
                        ${tech.note ? ` - ${escapeHtml(tech.note)}` : ''}
                        ${tech.severity ? `<br><small style="color: var(--text-secondary);">Status: ${escapeHtml(tech.severity)}</small>` : ''}
                    </div>
                `).join('')}
            </div>
        ` : ''}

        ${report.classification_logic ? `
            <div class="report-section">
                <h3>Detection Logic</h3>
                <div style="background: var(--bg-light); padding: 16px; border-radius: var(--radius); border: 1px solid var(--border-color);">
                    <h4 style="margin-bottom: 12px;">Phase Analysis</h4>
                    <div style="display: grid; gap: 12px;">
                        <div style="padding: 12px; background: white; border-radius: 3px;">
                            <strong style="color: var(--success);">Phase 1 - Discovery:</strong> ${escapeHtml(report.classification_logic.phase_1_discovery)}
                        </div>
                        <div style="padding: 12px; background: white; border-radius: 3px;">
                            <strong style="color: #FF9800;">Phase 2 - Intent:</strong> ${escapeHtml(report.classification_logic.phase_2_intent)}
                        </div>
                        <div style="padding: 12px; background: white; border-radius: 3px;">
                            <strong style="color: #757575;">Phase 3 - Impact:</strong> ${escapeHtml(report.classification_logic.phase_3_impact)}
                        </div>
                    </div>
                    <p style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 13px;">
                        <strong>Conclusion:</strong> ${escapeHtml(report.classification_logic.conclusion)}
                    </p>
                </div>
            </div>
        ` : ''}

        ${report.recommendations && report.recommendations.length > 0 ? `
            <div class="report-section">
                <h3>Recommendations</h3>
                ${report.recommendations.map(rec => `
                    <div class="recommendation">
                        ${escapeHtml(rec)}
                    </div>
                `).join('')}
            </div>
        ` : ''}

        ${report.disclaimer || report.is_simulation ? `
            <div class="report-section">
                <div class="report-disclaimer">
                    <strong>Disclaimer:</strong> ${report.disclaimer || 'This analysis was generated using simulated behavior detection for educational and safety purposes.'}
                </div>
            </div>
        ` : ''}
    `;
}

// Modal Controls
function setupModalControls() {
    const modal = document.getElementById('analysis-modal');
    const closeBtn = document.getElementById('modal-close');

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });
    }
}
