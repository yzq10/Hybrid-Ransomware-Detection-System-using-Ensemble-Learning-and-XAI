import { displayMainResult } from './main.js';


// History page functionality
let historyData = [];

// Initialize history page when it becomes active
document.addEventListener('DOMContentLoaded', () => {
    const historyNavLink = document.querySelector('[data-section="history"]');
    if (historyNavLink) {
        historyNavLink.addEventListener('click', () => {
            setTimeout(() => {
                initializeHistoryPage();
            }, 100);
        });
    }
});

function initializeHistoryPage() {
    const historySection = document.getElementById('history-section');
    if (historySection && historySection.classList.contains('active')) {
        loadHistoryData();
    }
}

function loadHistoryData() {
    const loadingDiv = document.getElementById('history-loading');
    const contentDiv = document.getElementById('history-content');
    
    if (loadingDiv) loadingDiv.style.display = 'block';
    if (contentDiv) contentDiv.style.display = 'none';
    
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            historyData = data;
            displayHistoryData();
            if (loadingDiv) loadingDiv.style.display = 'none';
            if (contentDiv) contentDiv.style.display = 'block';
        })
        .catch(error => {
            console.error('Error loading history:', error);
            if (loadingDiv) {
                loadingDiv.innerHTML = '<p>Error loading history data</p>';
            }
        });
}

function displayHistoryData() {
    const statsDiv = document.getElementById('history-stats');
    const tableDiv = document.getElementById('history-table');
    
    if (!statsDiv || !tableDiv) return;
    
    // Display statistics
    const totalCount = historyData.length;
    const threatCount = historyData.filter(item => item.prediction === 1).length;
    const safeCount = historyData.filter(item => item.prediction === 0).length;
    const autoCount = historyData.filter(item => item.source === 'auto').length;
    const manualCount = historyData.filter(item => item.source === 'manual').length;
    
    statsDiv.innerHTML = `
        <div class="stats">
            <div class="stat-item">
                <div class="stat-icon"><i class="fas fa-file"></i></div>
                <div class="stat-value">${totalCount}</div>
                <div class="stat-label">Total Analyzed</div>
            </div>
            <div class="stat-item threat">
                <div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="stat-value">${threatCount}</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-item safe">
                <div class="stat-icon"><i class="fas fa-check-circle"></i></div>
                <div class="stat-value">${safeCount}</div>
                <div class="stat-label">Safe Files</div>
            </div>
            <div class="stat-item" style="background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%);">
                <div class="stat-icon" style="color: #4caf50;"><i class="fas fa-eye"></i></div>
                <div class="stat-value">${autoCount}</div>
                <div class="stat-label">Auto-Detected</div>
            </div>
        </div>
    `;
    
    // Display table
    tableDiv.innerHTML = `
        <div class="history-table-container">
            <table class="history-table">
                <thead>
                    <tr>
                        <th><i class="fas fa-clock"></i> Timestamp</th>
                        <th><i class="fas fa-file"></i> Filename</th>
                        <th><i class="fas fa-source"></i> Source</th>
                        <th><i class="fas fa-shield-alt"></i> Result</th>
                        <th><i class="fas fa-eye"></i> Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${historyData.map(item => `
                        <tr>
                            <td class="timestamp">${new Date(item.timestamp).toLocaleString()}</td>
                            <td><strong>${item.filename}</strong></td>
                            <td><span class="source-badge ${item.source}">${item.source.toUpperCase()}</span></td>
                            <td><span class="result-badge ${item.prediction ? 'threat' : 'safe'}">${item.prediction ? 'THREAT' : 'SAFE'}</span></td>
                            <td><button class="btn-small" data-result-id="${item.id}"><i class="fas fa-search"></i> View Details</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    // Add this after the innerHTML assignment in displayHistoryData()
    document.querySelectorAll('.btn-small[data-result-id]').forEach(button => {
        button.addEventListener('click', function() {
            const resultId = this.getAttribute('data-result-id');
            showResultDetails(resultId);
        });
    });
}

function viewDetails(id) {
    fetch(`/api/result/${id}`)
        .then(response => response.json())
        .then(data => {
            showDetailsModal(data);
        })
        .catch(error => {
            console.error('Error loading details:', error);
        });
}

function showDetailsModal(data) {
    // Create modal to show detailed analysis results
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>${data.filename} - Analysis Details</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <pre>${JSON.stringify(data.analysis_result, null, 2)}</pre>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function closeModal() {
    const modal = document.querySelector('.modal');
    if (modal) {
        modal.remove();
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add this JavaScript to your existing script.js or main.js

// Function to show result details section
function showResultDetails(resultId) {
    console.log('🔥 showResultDetails called with ID:', resultId);
    
    // Hide all other sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.style.display = 'none';
        section.classList.remove('active');
    });
    
    // Show result details section
    const detailsSection = document.getElementById('result-details-section');
    detailsSection.style.display = 'block';
    detailsSection.classList.add('active');
    
    // ✅ DON'T clear navbar - keep history active or set details as active
    // Update navbar to show we're in a details view
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    // Keep history highlighted since details is part of history
    const historyNavLink = document.querySelector('[data-section="history"]');
    if (historyNavLink) {
        historyNavLink.classList.add('active');
    }
    
    // Load the result details
    loadResultDetails(resultId);
}

function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.style.display = 'none';
        section.classList.remove('active');
    });
    
    // Show target section
    const targetSection = document.getElementById(sectionName + '-section');
    if (targetSection) {
        targetSection.style.display = 'block';
        targetSection.classList.add('active');
    }
    
    // Update navbar
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-section="${sectionName}"]`)?.classList.add('active');
}

// Function to load result details from API
async function loadResultDetails(resultId) {
    try {
        console.log(`Loading details for result ID: ${resultId}`);
        
        // Show loading state
        document.getElementById('detail-filename').textContent = 'Loading...';
        document.getElementById('metadata-content').innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading metadata...</div>';
        document.getElementById('detail-results-area').innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading analysis results...</div>';
        
        console.log('🔥 DEBUG: Initial loading state set');
        
        // Fetch result details from your Flask route
        const response = await fetch(`/api/result-details/${resultId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Update filename
        document.getElementById('detail-filename').textContent = data.filename;
        
        // Update metadata
        updateMetadata(data);
        
        console.log('🔥 DEBUG: About to call displayResultDetails');
        console.log('🔥 DEBUG: Container before displayResultDetails:', document.getElementById('detail-results-area').innerHTML);
        
        // Display analysis results using existing function
        displayResultDetails(data.analysis_result, 'detail-results-area', data.filename);
        
        console.log('🔥 DEBUG: After displayResultDetails call');
        
        // Check content after a delay
        setTimeout(() => {
            console.log('🔥 DEBUG: Container content after 1 second:', document.getElementById('detail-results-area').innerHTML);
        }, 1000);

        console.log('✅ Result details loaded successfully');
        
    } catch (error) {
        console.error('❌ Error loading result details:', error);
        
        // Show error message
        document.getElementById('detail-filename').textContent = 'Error Loading Details';
        document.getElementById('metadata-content').innerHTML = `
            <div class="alert alert-danger">
                <h6><i class="fas fa-exclamation-triangle"></i> Error</h6>
                <p>Unable to load analysis details: ${error.message}</p>
            </div>
        `;
        document.getElementById('detail-results-area').innerHTML = `
            <div class="alert alert-danger">
                <h5><i class="fas fa-exclamation-triangle"></i> Error Loading Results</h5>
                <p>Unable to display analysis details. Please try again.</p>
            </div>
        `;
    }
}

// Function to update metadata display
function updateMetadata(data) {
    const metadataHtml = `
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Analysis ID:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">#${data.result_id}</span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Timestamp:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">${data.timestamp}</span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">File Hash:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529; word-break: break-all;">${data.file_hash || 'N/A'}</span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Source:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">
                ${data.source === 'manual' ? '<i class="fas fa-user"></i> Manual Upload' : 
                  data.source === 'auto' ? '<i class="fas fa-robot"></i> Auto Detection' : data.source}
            </span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Final Prediction:</span>
            <span class="metadata-value">
                ${data.prediction === 1 ? 
                    '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle"></i> Ransomware</span>' :
                    '<span class="badge bg-success"><i class="fas fa-shield-alt"></i> Benign</span>'
                }
            </span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Analysis Mode:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">${data.analysis_result?.analysis_mode || 'unknown'}</span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid #e9ecef;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Decision Stage:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">${(data.analysis_result?.decision_stage || 'unknown').replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
        </div>
        
        <div class="metadata-item" style="display: flex; justify-content: space-between; padding: 0.5rem 0;">
            <span class="metadata-label" style="font-weight: 600; color: #495057;">Total Execution Time:</span>
            <span class="metadata-value" style="font-family: 'Courier New', monospace; color: #212529;">${(data.analysis_result?.total_execution_time || 0).toFixed(2)}s</span>
        </div>
    `;
    
    document.getElementById('metadata-content').innerHTML = metadataHtml;

        // ADD THIS - Apply hash truncation after metadata is populated
    setTimeout(() => {
        applyHashTruncation();
    }, 100);
}

// ========================================
// HASH TRUNCATION FUNCTIONALITY
// ========================================

function createTruncatedHash(fullHash, maxLength = 16) {
    const hashElement = document.createElement('span');
    hashElement.className = 'file-hash-truncated';
    hashElement.setAttribute('data-full-hash', fullHash);
    
    const truncated = fullHash.length > maxLength 
        ? fullHash.substring(0, maxLength) + '...' 
        : fullHash;
    
    hashElement.textContent = truncated;
    return hashElement;
}

function applyHashTruncation() {
    const metadataItems = document.querySelectorAll('.metadata-item');
    
    metadataItems.forEach(item => {
        const label = item.querySelector('.metadata-label');
        const value = item.querySelector('.metadata-value');
        
        if (label && value && label.textContent.toLowerCase().includes('hash')) {
            const fullHash = value.textContent.trim();
            
            if (fullHash.length > 20) {
                value.innerHTML = '';
                const truncatedHashElement = createTruncatedHash(fullHash, 16);
                value.appendChild(truncatedHashElement);
            }
        }
    });
}

// Function to display result details (reuse existing display logic)
// function displayResultDetails(analysisResult, containerId, filename = 'Detail View') {
//     const targetContainer = document.getElementById(containerId);
    
//     const confidence = (analysisResult.confidence * 100).toFixed(1);
//     const badgeClass = analysisResult.final_prediction === 0 ? 'result-safe' : 'result-threat';
//     const badgeIcon = analysisResult.final_prediction === 0 ? 'fa-shield-alt' : 'fa-exclamation-triangle';
    
//     targetContainer.innerHTML = `
//         <div class="result-card">
//             <div class="result-header">
//                 <h3>${filename}</h3>
//                 <div class="result-badge ${badgeClass}">
//                     <i class="fas ${badgeIcon}"></i>
//                     ${analysisResult.final_label} (${confidence}%)
//                 </div>
//             </div>
//             <div class="result-body">
                
//                 <!-- Signature Analysis Section with Expandable Content -->
//                 <div class="analysis-section">
//                     <h4 class="section-header" data-section="signature-details" style="cursor: pointer;">
//                         <i class="fas fa-fingerprint"></i> Signature Analysis (VirusTotal)
//                         <span class="stage-status stage-completed">
//                             <i class="fas fa-check"></i>
//                             Completed
//                         </span>
//                         <i class="fas fa-chevron-down toggle-icon" style="float: right; transition: transform 0.3s;"></i>
//                     </h4>
                    
//                     <!-- Basic Info (Always Visible) -->
//                     <div class="analysis-details">
//                         <div class="detail-item">
//                             <span class="detail-label">Decision:</span>
//                             <span class="detail-value">${analysisResult.signature_analysis?.decision || 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Confidence:</span>
//                             <span class="detail-value">${analysisResult.signature_analysis?.confidence ? (analysisResult.signature_analysis.confidence * 100).toFixed(1) + '%' : '0.0%'}</span>
//                         </div>
//                     </div>
                    
//                     <!-- Expandable Details -->
//                     <div id="signature-details" class="collapsible-content" style="display: none; margin-top: 1rem; border-top: 1px solid #e0e0e0; padding-top: 1rem;">
//                         <div class="detail-item">
//                             <span class="detail-label">Action:</span>
//                             <span class="detail-value">${analysisResult.signature_analysis?.action || 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Stage:</span>
//                             <span class="detail-value">${analysisResult.signature_analysis?.stage || 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">File Hash:</span>
//                             <span class="detail-value" style="font-family: monospace; font-size: 0.9em; word-break: break-all;">${analysisResult.signature_analysis?.file_hash || 'N/A'}</span>
//                         </div>
//                         <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 6px;">
//                             <strong>Reason:</strong> ${analysisResult.signature_analysis?.reason || 'N/A'}
//                         </div>
//                     </div>
//                 </div>
                
//                 <!-- Static Analysis Section with Expandable Content -->
//                 <div class="analysis-section">
//                     <h4 class="section-header" data-section="static-details" style="cursor: pointer;">
//                         <i class="fas fa-file-code"></i> Static Analysis (PE Features)
//                         <span class="stage-status stage-completed">
//                             <i class="fas fa-check"></i>
//                             Completed
//                         </span>
//                         <i class="fas fa-chevron-down toggle-icon" style="float: right; transition: transform 0.3s;"></i>
//                     </h4>
                    
//                     <!-- Basic Info (Always Visible) -->
//                     <div class="analysis-details">
//                         <div class="detail-item">
//                             <span class="detail-label">Prediction:</span>
//                             <span class="detail-value">
//                                 <span style="background: ${analysisResult.static_analysis?.prediction === 0 ? '#4caf50' : '#f44336'}; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.9rem;">
//                                     ${analysisResult.static_analysis?.prediction_label || 'N/A'}
//                                 </span>
//                             </span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Confidence:</span>
//                             <span class="detail-value">${analysisResult.static_analysis?.confidence ? (analysisResult.static_analysis.confidence * 100).toFixed(1) + '%' : 'N/A'}</span>
//                         </div>
//                     </div>
                    
//                     <!-- Confidence Bar -->
//                     <div class="confidence-bar" style="margin: 1rem 0; height: 8px; background: #e0e0e0; border-radius: 4px;">
//                         <div class="confidence-level" style="width: ${analysisResult.static_analysis?.confidence ? (analysisResult.static_analysis.confidence * 100).toFixed(1) : 0}%; height: 100%; background: ${analysisResult.static_analysis?.prediction === 1 ? '#f44336' : '#4caf50'}; border-radius: 4px;"></div>
//                     </div>
                    
//                     <!-- Expandable Details -->
//                     <div id="static-details" class="collapsible-content" style="display: none; margin-top: 1rem; border-top: 1px solid #e0e0e0; padding-top: 1rem;">
//                         <div class="detail-item">
//                             <span class="detail-label">Benign Probability:</span>
//                             <span class="detail-value">${analysisResult.static_analysis?.probabilities?.benign ? (analysisResult.static_analysis.probabilities.benign * 100).toFixed(1) + '%' : 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Ransomware Probability:</span>
//                             <span class="detail-value">${analysisResult.static_analysis?.probabilities?.ransomware ? (analysisResult.static_analysis.probabilities.ransomware * 100).toFixed(1) + '%' : 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Feature Count:</span>
//                             <span class="detail-value">${analysisResult.static_analysis?.feature_count || 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Execution Time:</span>
//                             <span class="detail-value">${analysisResult.static_analysis?.execution_time?.toFixed(3) || 'N/A'}s</span>
//                         </div>
                        
//                         <!-- Ensemble Details -->
//                         ${analysisResult.static_analysis?.ensemble_details ? `
//                             <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 6px;">
//                                 <strong>🏆 Static Ensemble Voting Results:</strong>
//                                 <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem;">
//                                     ${Object.entries(analysisResult.static_analysis.ensemble_details.individual_models || {}).map(([model, details]) => `
//                                         <div style="padding: 0.5rem; background: white; border-radius: 4px; border: 1px solid #e0e0e0;">
//                                             <strong>${model}:</strong> 
//                                             <span style="color: ${details.prediction === 1 ? '#f44336' : '#4caf50'};">
//                                                 ${details.prediction_label} (${(details.confidence * 100).toFixed(1)}%)
//                                             </span>
//                                         </div>
//                                     `).join('')}
//                                 </div>
//                             </div>
//                         ` : ''}
//                     </div>
//                 </div>
                
//                 <!-- Dynamic Analysis Section with Expandable Content -->
//                 <div class="analysis-section">
//                     <h4 class="section-header" data-section="dynamic-details" style="cursor: pointer;">
//                         <i class="fas fa-play-circle"></i> Dynamic Analysis
//                         <span class="stage-status stage-completed">
//                             <i class="fas fa-check"></i>
//                             Completed
//                         </span>
//                         <i class="fas fa-chevron-down toggle-icon" style="float: right; transition: transform 0.3s;"></i>
//                     </h4>
                    
//                     <!-- Basic Info (Always Visible) -->
//                     <div class="analysis-details">
//                         <div class="detail-item">
//                             <span class="detail-label">Prediction:</span>
//                             <span class="detail-value">
//                                 <span style="background: ${analysisResult.dynamic_analysis?.prediction === 0 ? '#4caf50' : '#f44336'}; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.9rem;">
//                                     ${analysisResult.dynamic_analysis?.prediction_label || 'N/A'}
//                                 </span>
//                             </span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Confidence:</span>
//                             <span class="detail-value">${analysisResult.dynamic_analysis?.confidence ? (analysisResult.dynamic_analysis.confidence * 100).toFixed(1) + '%' : 'N/A'}</span>
//                         </div>
//                     </div>
                    
//                     <!-- Confidence Bar -->
//                     <div class="confidence-bar" style="margin: 1rem 0; height: 8px; background: #e0e0e0; border-radius: 4px;">
//                         <div class="confidence-level" style="width: ${analysisResult.dynamic_analysis?.confidence ? (analysisResult.dynamic_analysis.confidence * 100).toFixed(1) : 0}%; height: 100%; background: ${analysisResult.dynamic_analysis?.prediction === 1 ? '#f44336' : '#4caf50'}; border-radius: 4px;"></div>
//                     </div>
                    
//                     <!-- Expandable Details -->
//                     <div id="dynamic-details" class="collapsible-content" style="display: none; margin-top: 1rem; border-top: 1px solid #e0e0e0; padding-top: 1rem;">
//                         <div class="detail-item">
//                             <span class="detail-label">Analysis Type:</span>
//                             <span class="detail-value">${analysisResult.dynamic_analysis?.analysis_type || 'N/A'}</span>
//                         </div>
//                         <div class="detail-item">
//                             <span class="detail-label">Execution Time:</span>
//                             <span class="detail-value">${analysisResult.dynamic_analysis?.execution_time?.toFixed(3) || 'N/A'}s</span>
//                         </div>
                        
//                         <!-- Ensemble Details -->
//                         ${analysisResult.dynamic_analysis?.ensemble_details ? `
//                             <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 6px;">
//                                 <strong>🏆 Dynamic Ensemble Voting Results:</strong>
//                                 <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem;">
//                                     ${Object.entries(analysisResult.dynamic_analysis.ensemble_details.individual_models || {}).map(([model, details]) => `
//                                         <div style="padding: 0.5rem; background: white; border-radius: 4px; border: 1px solid #e0e0e0;">
//                                             <strong>${model}:</strong> 
//                                             <span style="color: ${details.prediction === 'ransomware' ? '#f44336' : '#4caf50'};">
//                                                 ${details.prediction} (${(details.confidence * 100).toFixed(1)}%)
//                                             </span>
//                                         </div>
//                                     `).join('')}
//                                 </div>
//                             </div>
//                         ` : ''}
//                     </div>
//                 </div>
                
//             </div>
//         </div>
//     `;
    
//     // Add click handlers for collapsible sections
//     setTimeout(() => {
//         document.querySelectorAll('.section-header[data-section]').forEach(header => {
//             header.addEventListener('click', function() {
//                 const sectionId = this.getAttribute('data-section');
//                 const content = document.getElementById(sectionId);
//                 const icon = this.querySelector('.toggle-icon');
                
//                 if (content.style.display === 'none') {
//                     content.style.display = 'block';
//                     icon.style.transform = 'rotate(180deg)';
//                 } else {
//                     content.style.display = 'none';
//                     icon.style.transform = 'rotate(0deg)';
//                 }
//             });
//         });
//     }, 100);
// }
function displayResultDetails(analysisResult, containerId, filename = 'Detail View') {
    console.log('🔍 DEBUG: displayResultDetails called with:', {
        containerId,
        filename,
        analysisResult: analysisResult ? 'Present' : 'Missing'
    });
    
    const targetContainer = document.getElementById(containerId);
    console.log('🔍 DEBUG: Target container found:', {
        element: targetContainer ? 'Found' : 'Not found',
        id: targetContainer?.id,
        innerHTML: targetContainer?.innerHTML?.substring(0, 100) + '...',
        offsetHeight: targetContainer?.offsetHeight,
        offsetWidth: targetContainer?.offsetWidth,
        display: targetContainer ? getComputedStyle(targetContainer).display : 'N/A',
        visibility: targetContainer ? getComputedStyle(targetContainer).visibility : 'N/A'
    });
    
    // Check for existing results-area
    const originalResultsArea = document.getElementById('results-area');
    console.log('🔍 DEBUG: Original results-area:', {
        element: originalResultsArea ? 'Found' : 'Not found',
        id: originalResultsArea?.id,
        parentElement: originalResultsArea?.parentElement?.tagName,
        childrenCount: originalResultsArea?.children?.length
    });
    
    // Temporarily change the target for displayMainResult
    if (originalResultsArea) {
        originalResultsArea.id = 'temp-results-area';
        console.log('🔍 DEBUG: Changed original results-area ID to temp-results-area');
    }
    
    const originalTargetId = targetContainer.id;
    targetContainer.id = 'results-area';
    console.log('🔍 DEBUG: Changed target container ID from', originalTargetId, 'to results-area');
    
    // Verify the ID change worked
    const newResultsArea = document.getElementById('results-area');
    console.log('🔍 DEBUG: New results-area after ID change:', {
        element: newResultsArea ? 'Found' : 'Not found',
        isSameAsTarget: newResultsArea === targetContainer,
        innerHTML: newResultsArea?.innerHTML?.substring(0, 100) + '...'
    });
    
    // Clear existing content
    if (targetContainer) {
        const beforeClear = targetContainer.innerHTML;
        targetContainer.innerHTML = '';
        console.log('🔍 DEBUG: Cleared target container content:', {
            before: beforeClear.substring(0, 100) + '...',
            after: targetContainer.innerHTML
        });
    }
    
    console.log('🔍 DEBUG: About to call displayMainResult with:', {
        filename,
        analysisResultKeys: Object.keys(analysisResult || {})
    });
    
    // Use the exact same function as main page
    displayMainResult(filename, analysisResult);
    
    // Check what happened after displayMainResult
    setTimeout(() => {
        console.log('🔍 DEBUG: After displayMainResult (immediate check):', {
            targetContainerHTML: targetContainer?.innerHTML?.substring(0, 200) + '...',
            targetContainerChildren: targetContainer?.children?.length,
            firstChildClass: targetContainer?.children[0]?.className,
            resultsAreaHTML: document.getElementById('results-area')?.innerHTML?.substring(0, 200) + '...'
        });
    }, 10);
    
    // Check again after a delay
    setTimeout(() => {
        console.log('🔍 DEBUG: After displayMainResult (500ms delay):', {
            targetContainerHTML: targetContainer?.innerHTML?.substring(0, 200) + '...',
            targetContainerChildren: targetContainer?.children?.length,
            targetContainerDisplay: getComputedStyle(targetContainer).display,
            targetContainerVisibility: getComputedStyle(targetContainer).visibility,
            parentDisplay: getComputedStyle(targetContainer.parentElement).display,
            parentVisibility: getComputedStyle(targetContainer.parentElement).visibility
        });
        
        // Check if content exists but is hidden by CSS
        const resultCards = targetContainer.querySelectorAll('.result-card');
        console.log('🔍 DEBUG: Result cards found:', {
            count: resultCards.length,
            cards: Array.from(resultCards).map(card => ({
                className: card.className,
                display: getComputedStyle(card).display,
                visibility: getComputedStyle(card).visibility,
                height: card.offsetHeight,
                width: card.offsetWidth
            }))
        });
    }, 500);
    
    console.log('🔍 DEBUG: displayResultDetails completed, NOT restoring IDs');
}



// Back to history navigation
document.addEventListener('DOMContentLoaded', function() {
    const backButton = document.getElementById('back-to-history-btn');
    if (backButton) {
        backButton.addEventListener('click', function() {
            showSection('history');
        });
    }
    
    // ✅ ADD THIS HERE - inside the existing DOMContentLoaded
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            if (section) {
                showSection(section);
            }
        });
    });
});

// Update your existing history page button click handlers
// Replace the existing "Show Details" button onclick with:
// onclick="showResultDetails({{ result.id }})"

