// ========================================
// MAIN.JS - Full 3-Stage Pipeline Orchestrator
// ========================================
// This file handles the main Detection page functionality
// Coordinates: Signature → Static → Dynamic → Final Results

import { 
    API_ENDPOINTS, 
    showNotification, 
    validateFile, 
    formatFileSize,
    setupDragAndDrop,
    setupFileInput,
    processFiles,
    displayFileList,
    updateProgressBar,
    makeApiRequest,
    determineActualPrediction,
    formatAnalysisMode,
    toggleCollapsibleSection
} from './core.js';

import { generateDetectionStatsSection } from './signature.js';
import { generateStaticAnalysisSection } from './static.js';
import { generateDynamicXAIExplanationSection, generateDynamicEnsembleDetailsSection } from './dynamic.js';

// ========================================
// MAIN PIPELINE VARIABLES
// ========================================

let mainFilesToScan = [];
let mainScanResults = [];

// ========================================
// DOM ELEMENTS (Fixed to match actual HTML IDs)
// ========================================

const mainUploadArea = document.getElementById('upload-area');
const mainFileInput = document.getElementById('file-input');
const mainFileListContainer = document.getElementById('file-list-container');
const mainFileList = document.getElementById('file-list');
const mainScanButton = document.getElementById('scan-button');
const mainClearButton = document.getElementById('clear-button');
const mainLoading = document.getElementById('loading');
const mainLoadingText = document.getElementById('loading-text');
const mainProgressBar = document.getElementById('progress-fill');
const mainCurrentFile = document.getElementById('current-file');
const mainApiStatus = document.getElementById('api-status');
const mainStatusContent = document.getElementById('status-content');
const mainResultsContainer = document.getElementById('results-container');
const mainResultsArea = document.getElementById('results-area');
const mainTotalScanned = document.getElementById('total-scanned');
const mainSafeCount = document.getElementById('safe-count');
const mainThreatCount = document.getElementById('threat-count');
const mainDynamicAnalyzed = document.getElementById('dynamic-analyzed');

// ========================================
// CORE MAIN FUNCTIONS
// ========================================

/**
 * Initialize main detection page
 */
function initializeMainPage() {
    console.log('🔥 Initializing Main Detection Page...');
    
    if (!mainUploadArea || !mainFileInput) {
        console.log('Main upload elements not found, skipping main initialization');
        return;
    }
    
    // Setup file upload functionality
    setupMainFileUpload();
    
    // Setup button event listeners
    setupMainEventListeners();
    
    // Check system status
    checkMainSystemStatus();
    
    console.log('✅ Main Detection Page initialized');
}

/**
 * Setup main file upload functionality
 */
function setupMainFileUpload() {
    if (mainUploadArea && mainFileInput) {
        setupFileInput(mainUploadArea, mainFileInput, handleMainFiles);
        setupDragAndDrop(mainUploadArea, handleMainFiles);
    }
}

/**
 * Setup main event listeners
 */
function setupMainEventListeners() {
    if (mainScanButton) {
        mainScanButton.addEventListener('click', scanMainFiles);
    }
    
    if (mainClearButton) {
        mainClearButton.addEventListener('click', clearMainFiles);
    }
}

/**
 * Check main system status
 */
async function checkMainSystemStatus() {
    if (!mainStatusContent) return;
    
    try {
        mainStatusContent.innerHTML = `
            <div class="loading">
                <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
                <div>Checking system status...</div>
            </div>
        `;

        const response = await makeApiRequest(API_ENDPOINTS.MODEL_INFO);

        if (response.success && response.data.status === 'success') {
            displayMainSystemStatus(response.data);
        } else {
            throw new Error(response.error || 'Failed to get system status');
        }

    } catch (error) {
        console.error('Main system status check error:', error);
        mainStatusContent.innerHTML = `
            <div style="color: #c62828; padding: 1rem; background: #ffcdd2; border-radius: 8px;">
                <strong><i class="fas fa-wifi"></i> Connection Error:</strong> Cannot connect to analysis API<br>
                <small>Make sure the server is running</small>
            </div>
        `;
        disableMainUpload();
    }
}

/**
 * Display main system status
 */
function displayMainSystemStatus(statusData) {
    if (!mainStatusContent) return;
    
    const staticModel = statusData.static_model || {};
    const dynamicModel = statusData.dynamic_model || {};
    const cuckooStatus = statusData.cuckoo_status || { status: 'unknown' };
    
    const staticReady = staticModel.loaded || false;
    const dynamicReady = dynamicModel.loaded || false;
    const cuckooReady = cuckooStatus.status === 'connected';
    
    mainStatusContent.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
            <!-- Static Ensemble Models Section -->
            <div style="padding: 1.5rem; background: linear-gradient(135deg, ${staticReady ? '#e8f5e8' : '#fff3cd'} 0%, ${staticReady ? '#c8e6c9' : '#ffeaa7'} 100%); border-radius: 12px; border: 1px solid ${staticReady ? '#c8e6c9' : '#fdcb6e'};">
                <h3 style="margin: 0 0 1rem 0; color: ${staticReady ? '#2e7d32' : '#856404'}; display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-file-code" style="color: ${staticReady ? '#4caf50' : '#f39c12'};"></i>
                    Static Ensemble Models
                </h3>
                <div style="display: grid; gap: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid #28a745;">
                        <span><i class="fas fa-tree"></i> Random Forest</span>
                        <span style="color: #28a745; font-weight: 600;">
                            <i class="fas fa-check-circle"></i> Ready
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid #28a745;">
                        <span><i class="fas fa-vector-square"></i> SVM</span>
                        <span style="color: #28a745; font-weight: 600;">
                            <i class="fas fa-check-circle"></i> Ready
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid #28a745;">
                        <span><i class="fas fa-rocket"></i> XGBoost</span>
                        <span style="color: #28a745; font-weight: 600;">
                            <i class="fas fa-check-circle"></i> Ready
                        </span>
                    </div>
                </div>
                <div style="margin-top: 1rem; padding: 0.75rem; background: ${staticReady ? '#d4edda' : '#fff3cd'}; border-radius: 6px; text-align: center;">
                    <strong style="color: ${staticReady ? '#155724' : '#856404'};">
                        ${staticReady ? '✅ Static Models Ready' : '⚠️ Static Models Not Ready'}
                    </strong>
                </div>
            </div>

            <!-- Dynamic Analysis Section -->
            <div style="padding: 1.5rem; background: linear-gradient(135deg, ${dynamicReady && cuckooReady ? '#e8f5e8' : '#fff3cd'} 0%, ${dynamicReady && cuckooReady ? '#c8e6c9' : '#ffeaa7'} 100%); border-radius: 12px; border: 1px solid ${dynamicReady && cuckooReady ? '#c8e6c9' : '#fdcb6e'};">
                <h3 style="margin: 0 0 1rem 0; color: ${dynamicReady && cuckooReady ? '#2e7d32' : '#856404'}; display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-play-circle" style="color: ${dynamicReady && cuckooReady ? '#4caf50' : '#f39c12'};"></i>
                    Dynamic Analysis & Sandbox
                </h3>
                <div style="display: grid; gap: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${dynamicReady ? '#28a745' : '#dc3545'};">
                        <span><i class="fas fa-brain"></i> Dynamic Models</span>
                        <span style="color: ${dynamicReady ? '#28a745' : '#dc3545'}; font-weight: 600;">
                            <i class="fas ${dynamicReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> 
                            ${dynamicReady ? 'Ready' : 'Not Ready'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${cuckooReady ? '#28a745' : '#dc3545'};">
                        <span><i class="fas fa-cube"></i> Cuckoo Sandbox</span>
                        <span style="color: ${cuckooReady ? '#28a745' : '#dc3545'}; font-weight: 600;">
                            <i class="fas ${cuckooReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> 
                            ${cuckooReady ? 'Connected' : 'Disconnected'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid #28a745;">
                        <span><i class="fas fa-lightbulb"></i> XAI Explanations</span>
                        <span style="color: #28a745; font-weight: 600;">
                            <i class="fas fa-check-circle"></i> Ready
                        </span>
                    </div>
                </div>
                <div style="margin-top: 1rem; padding: 0.75rem; background: ${dynamicReady && cuckooReady ? '#d4edda' : '#fff3cd'}; border-radius: 6px; text-align: center;">
                    <strong style="color: ${dynamicReady && cuckooReady ? '#155724' : '#856404'};">
                        ${dynamicReady && cuckooReady ? '✅ Dynamic Analysis Ready' : '⚠️ Limited Functionality'}
                    </strong>
                </div>
            </div>
        </div>
        
        <div style="margin-top: 1.5rem; padding: 1rem; background: ${staticReady ? '#e3f2fd' : '#fff3cd'}; border-radius: 8px; color: ${staticReady ? '#1565c0' : '#856404'}; border-left: 4px solid ${staticReady ? '#2196f3' : '#ffc107'};">
            <strong><i class="fas fa-info-circle"></i> Pipeline Status:</strong> 
            ${staticReady ? 'Full 3-stage analysis pipeline (Signature → Static → Dynamic) available with ensemble ML models and XAI explanations' : 'Limited analysis available - some components may be offline'}
        </div>
    `;

    if (!staticReady) {
        disableMainUpload();
    } else {
        enableMainUpload();
    }
}

/**
 * Disable main upload interface
 */
function disableMainUpload() {
    if (mainUploadArea) {
        mainUploadArea.style.pointerEvents = 'none';
        mainUploadArea.style.opacity = '0.6';
    }
    if (mainScanButton) {
        mainScanButton.disabled = true;
    }
}

/**
 * Enable main upload interface
 */
function enableMainUpload() {
    if (mainUploadArea) {
        mainUploadArea.style.pointerEvents = 'auto';
        mainUploadArea.style.opacity = '1';
    }
    if (mainScanButton) {
        mainScanButton.disabled = false;
    }
}

// ========================================
// MAIN FILE HANDLING FUNCTIONS
// ========================================

/**
 * Handle main file selection
 */
function handleMainFiles(fileList) {
    const result = processFiles(fileList, mainFilesToScan);
    
    // Show errors for invalid files
    result.errors.forEach(error => {
        showNotification(error, 'error');
    });
    
    // Add valid files to the list
    mainFilesToScan.push(...result.validFiles);
    
    // Update the file list display
    updateMainFileList();
    
    // Show success notification if files were added
    if (result.validFiles.length > 0) {
        showNotification(`${result.validFiles.length} file(s) added for analysis`, 'success');
    }
}

/**
 * Update main file list display
 */
function updateMainFileList() {
    displayFileList(mainFilesToScan, mainFileListContainer, removeMainFile);
}

/**
 * Remove a file from main files list
 */
function removeMainFile(index) {
    if (index >= 0 && index < mainFilesToScan.length) {
        const removedFile = mainFilesToScan.splice(index, 1)[0];
        updateMainFileList();
        showNotification(`${removedFile.name} removed from analysis`, 'info');
    }
}

/**
 * Clear all main files
 */
function clearMainFiles() {
    mainFilesToScan = [];
    updateMainFileList();
    hideMainResults();
    showNotification('All files cleared', 'info');
}

/**
 * Hide main results container
 */
function hideMainResults() {
    if (mainResultsContainer) {
        mainResultsContainer.style.display = 'none';
    }
    if (mainResultsArea) {
        mainResultsArea.innerHTML = '';
    }
}

// ========================================
// MAIN SCANNING FUNCTIONS
// ========================================

/**
 * Scan all main files with full 3-stage pipeline
 */
async function scanMainFiles() {
    if (mainFilesToScan.length === 0) {
        showNotification('No files selected for analysis', 'error');
        return;
    }
    
    // Show loading and disable buttons
    showMainLoading(true);
    
    // Clear previous results
    mainScanResults = [];
    clearMainResultsArea();
    
    let safeCnt = 0;
    let threatCnt = 0;
    let dynamicCnt = 0;
    
    console.log(`🔥 Starting full 3-stage analysis for ${mainFilesToScan.length} files...`);
    
    for (let i = 0; i < mainFilesToScan.length; i++) {
        const file = mainFilesToScan[i];
        
        try {
            // Update progress
            updateMainProgress(i + 1, mainFilesToScan.length, file.name, 'signature');
            
            // Perform full 3-stage analysis
            const result = await performFullAnalysis(file);
            
            if (result.success) {
                mainScanResults.push(result.data);
                displayMainResult(file.name, result.data);
                
                // Update counters
                if (result.data.final_prediction === 1) {
                    threatCnt++;
                } else {
                    safeCnt++;
                }
                
                // Count dynamic analyses
                if (result.data.dynamic_analysis && result.data.dynamic_analysis.performed) {
                    dynamicCnt++;
                }
            } else {
                displayMainError(file.name, result.error);
            }
            
        } catch (error) {
            console.error(`Analysis error for ${file.name}:`, error);
            displayMainError(file.name, error.message);
        }
    }
    
    // Update final statistics
    updateMainStats(safeCnt, threatCnt, dynamicCnt);
    
    // Show results and hide loading
    showMainResults();
    showMainLoading(false);
    
    // Show completion notification
    const totalFiles = safeCnt + threatCnt;
    showNotification(`Analysis complete! ${totalFiles} files processed, ${threatCnt} threats detected.`, 'success');
}

/**
 * Perform full 3-stage analysis on a single file
 */
async function performFullAnalysis(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    return await makeApiRequest(API_ENDPOINTS.SCAN, {
        method: 'POST',
        body: formData
    });
}

// ========================================
// MAIN UI FUNCTIONS
// ========================================

/**
 * Show/hide main loading screen
 */
function showMainLoading(show) {
    if (mainLoading) {
        mainLoading.style.display = show ? 'flex' : 'none';
    }
    
    if (mainScanButton) {
        mainScanButton.disabled = show;
    }
    
    if (mainClearButton) {
        mainClearButton.disabled = show;
    }
}

/**
 * Update main analysis progress
 */
function updateMainProgress(current, total, fileName, stage) {
    const progress = (current / total) * 100;
    
    if (mainProgressBar) {
        mainProgressBar.style.width = `${progress}%`;
    }
    
    if (mainCurrentFile) {
        mainCurrentFile.innerHTML = `<i class="fas fa-file"></i> Analyzing: ${fileName}`;
    }
    
    // Stage information
    const stageInfo = {
        'signature': {
            text: 'Signature Analysis',
            description: 'Checking VirusTotal database for known threats',
            icon: 'fa-fingerprint'
        },
        'static': {
            text: 'Static Analysis',
            description: 'Analyzing PE structure with ensemble ML models',
            icon: 'fa-file-code'
        },
        'dynamic': {
            text: 'Dynamic Analysis',
            description: 'Behavioral analysis with Cuckoo Sandbox',
            icon: 'fa-play-circle'
        }
    };
    
    const currentStageInfo = stageInfo[stage] || stageInfo['signature'];
    
    if (mainLoadingText) {
        mainLoadingText.innerHTML = `<i class="fas ${currentStageInfo.icon}"></i> ${currentStageInfo.text} (${current}/${total})`;
    }
}

/**
 * Update main statistics display
 */
function updateMainStats(safeCount, threatCount, dynamicCount) {
    if (mainTotalScanned) {
        mainTotalScanned.textContent = safeCount + threatCount;
    }
    if (mainSafeCount) {
        mainSafeCount.textContent = safeCount;
    }
    if (mainThreatCount) {
        mainThreatCount.textContent = threatCount;
    }
    if (mainDynamicAnalyzed) {
        mainDynamicAnalyzed.textContent = dynamicCount;
    }
}

/**
 * Show main results container
 */
function showMainResults() {
    if (mainResultsContainer) {
        mainResultsContainer.style.display = 'block';
    }
}

/**
 * Clear main results area
 */
function clearMainResultsArea() {
    if (mainResultsArea) {
        mainResultsArea.innerHTML = '';
    }
}

// ========================================
// MAIN RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Display main analysis result
 */
function displayMainResult(fileName, result) {
    if (!mainResultsArea) return;
    
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    console.log('🔥 DEBUG: About to call determineActualPrediction with:', result);
    const actualPrediction = determineActualPrediction(result);
    const confidence = (result.confidence * 100).toFixed(1);
    const analysisMode = formatAnalysisMode(result.analysis_mode);
    const badgeClass = actualPrediction === 0 ? 'result-safe' : 'result-threat';
    const badgeIcon = actualPrediction === 0 ? 'fa-shield-alt' : 'fa-exclamation-triangle';
    
    console.log('🔥 DEBUG: About to generate signature section');
    const signatureSection = generateSignatureAnalysisSection(result.signature_analysis);
    console.log('🔥 DEBUG: Signature section generated successfully');
    
    console.log('🔥 DEBUG: About to generate static section');
    const staticSection = generateStaticAnalysisSection(result.static_analysis);
    console.log('🔥 DEBUG: Static section generated successfully');
    
    console.log('🔥 DEBUG: About to generate dynamic section');
    const dynamicSection = generateDynamicAnalysisSection(result.dynamic_analysis);
    console.log('🔥 DEBUG: Dynamic section generated successfully');
    
    console.log('🔥 DEBUG: About to generate final decision section');
    const finalSection = generateFinalDecisionSection(result);
    console.log('🔥 DEBUG: Final section generated successfully');
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3>${fileName}</h3>
            <div class="result-badge ${badgeClass}">
                <i class="fas ${badgeIcon}"></i>
                ${result.final_label} (${confidence}%)
            </div>
        </div>
        <div class="result-body">
            ${signatureSection}
            ${staticSection}
            ${dynamicSection}
            ${finalSection}
        </div>
    `;
    
    console.log('🔥 DEBUG: About to append to DOM');
    const currentResultsArea = document.getElementById('results-area');
    if (currentResultsArea) {
        currentResultsArea.appendChild(resultCard);
    } else {
        console.error('No results-area found for appendChild');
    }
    console.log('🔥 DEBUG: Successfully appended to DOM');
}

/**
 * Display main analysis error
 */
function displayMainError(fileName, errorMessage) {
    if (!mainResultsArea) return;
    
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card result-error';
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3>${fileName}</h3>
            <div class="result-badge" style="background-color: #f44336;">
                <i class="fas fa-times-circle"></i>
                Error
            </div>
        </div>
        <div class="result-body">
            <div style="background: #ffcdd2; padding: 1rem; border-radius: 8px; color: #c62828;">
                <strong><i class="fas fa-bug"></i> Analysis Error:</strong><br>
                ${errorMessage}
            </div>
        </div>
    `;
    
    mainResultsArea.appendChild(resultCard);
}

// ========================================
// MAIN RESULT GENERATION FUNCTIONS
// ========================================

/**
 * Generate signature analysis section
 */
function generateSignatureAnalysisSection(signatureAnalysis) {
    if (!signatureAnalysis || !signatureAnalysis.performed) {
        return `
            <div class="analysis-section">
                <h4>
                    <i class="fas fa-fingerprint"></i> Signature Analysis
                    <span class="stage-status stage-skipped">
                        <i class="fas fa-minus-circle"></i>
                        Skipped
                    </span>
                </h4>
                <p style="color: #666; font-style: italic;">
                    <i class="fas fa-info-circle"></i>
                    Signature analysis was not performed.
                </p>
            </div>
        `;
    }
    
    const confidence = (signatureAnalysis.confidence * 100).toFixed(1);
    const statusClass = 'stage-completed';
    
    return `
        <div class="signature-section">
            <h5><i class="fas fa-fingerprint"></i> Signature Analysis (VirusTotal)</h5>
            <div class="hash-display">
                <strong>SHA256:</strong> ${signatureAnalysis.file_hash || 'Not available'}
            </div>
            <div class="analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Decision:</span>
                    <span class="detail-value">${signatureAnalysis.decision}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${confidence}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Action:</span>
                    <span class="detail-value">${signatureAnalysis.action || 'N/A'}</span>
                </div>
            </div>
            ${generateDetectionStatsSection ? generateDetectionStatsSection(signatureAnalysis) : ''}
            <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 6px;">
                <strong>Reason:</strong> ${signatureAnalysis.reason}
            </div>
            ${signatureAnalysis.execution_time ? `<small style="color: #666; margin-top: 0.5rem; display: block;"><i class="fas fa-clock"></i> Execution time: ${(signatureAnalysis.execution_time * 1000).toFixed(0)}ms</small>` : ''}
        </div>
    `;
}

function generateDynamicEnsembleDetailsFromExplanation(explanation, ensembleDetails) {
    if (!explanation || !explanation.model_explanations) {
        return '';
    }
    
    // Check if we have ensemble details with predictions
    if (ensembleDetails && ensembleDetails.individual_models) {
        return generateDynamicEnsembleDetailsSection(ensembleDetails);
    } else {
        // Extract model predictions from model_explanations (we don't have confidence, so we'll skip it)
        const models = explanation.model_explanations;
        let content = `
            <div class="ensemble-section">
                <h5><i class="fas fa-vote-yea"></i> Dynamic Ensemble Model Analysis</h5>
                <div class="voting-summary">
        `;
        
        Object.keys(models).forEach(modelName => {
            const nameMapping = {
                'randomforest': 'Random Forest',
                'xgboost': 'XGBoost',
                'svm': 'SVM'
            };
            const modelDisplayName = nameMapping[modelName] || modelName;
            
            content += `
                <div class="model-vote">
                    <div class="model-name">${modelDisplayName}</div>
                    <div class="vote-result">
                        <i class="fas fa-microscope"></i>
                        Feature Analysis Available
                    </div>
                </div>
            `;
        });
        
        content += `</div></div>`;
        return content;
    }
}

/**
 * Generate dynamic analysis section
 */
function generateDynamicAnalysisSection(dynamicAnalysis) {
    if (!dynamicAnalysis || !dynamicAnalysis.performed) {
        return `
            <div class="analysis-section">
                <h4>
                    <i class="fas fa-play-circle"></i> Dynamic Analysis (Behavioral)
                    <span class="stage-status stage-skipped">
                        <i class="fas fa-minus-circle"></i>
                        Skipped
                    </span>
                </h4>
                <p style="color: #666; font-style: italic;">
                    <i class="fas fa-info-circle"></i>
                    ${dynamicAnalysis?.reason || 'Dynamic analysis was not performed.'}
                </p>
            </div>
        `;
    }
    
    const confidence = (dynamicAnalysis.confidence * 100).toFixed(1);
    const analysisType = dynamicAnalysis.analysis_type || 'single_model';
    const statusClass = 'stage-completed';
    
    return `
        <div class="analysis-section">
            <h4>
                <i class="fas fa-play-circle"></i> Dynamic Analysis ${analysisType === 'ensemble' ? '(Ensemble ML)' : '(Behavioral)'}
                <span class="stage-status ${statusClass}">
                    <i class="fas fa-check"></i>
                    Completed
                </span>
            </h4>
            <div class="analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Prediction:</span>
                    <span class="detail-value">
                        <i class="fas ${dynamicAnalysis.prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt'}"></i>
                        ${dynamicAnalysis.prediction_label}
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${confidence}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Benign Probability:</span>
                    <span class="detail-value">${(dynamicAnalysis.probabilities.benign * 100).toFixed(1)}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Ransomware Probability:</span>
                    <span class="detail-value">${(dynamicAnalysis.probabilities.ransomware * 100).toFixed(1)}%</span>
                </div>
            </div>
            <div class="confidence-bar">
                <div class="confidence-level" style="width: ${confidence}%; background: ${dynamicAnalysis.prediction === 1 ? '#f44336' : '#4caf50'};"></div>
            </div>
            ${dynamicAnalysis.ensemble_details && dynamicAnalysis.ensemble_details.individual_models ? 
                generateDynamicEnsembleDetailsSection(dynamicAnalysis.ensemble_details) : 
                generateDynamicEnsembleDetailsFromExplanation(dynamicAnalysis.explanation, dynamicAnalysis.ensemble_details)}
            ${dynamicAnalysis.explanation ? generateDynamicXAIExplanationSection(dynamicAnalysis.explanation, dynamicAnalysis.ensemble_details) : ''}
            ${dynamicAnalysis.execution_time ? `<small style="color: #666; margin-top: 0.5rem; display: block;"><i class="fas fa-clock"></i> Execution time: ${(dynamicAnalysis.execution_time * 1000).toFixed(0)}ms</small>` : ''}
        </div>
    `;
}

/**
 * Generate final decision section
 */
function generateFinalDecisionSection(result) {
    const confidence = (result.confidence * 100).toFixed(1);
    const actualPrediction = result.final_prediction; // Use final_prediction directly
    const resultIcon = actualPrediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt';
    const resultColor = actualPrediction === 1 ? '#f44336' : '#4caf50'; // Red for ransomware, green for benign
    
    return `
        <div class="analysis-section final-result" style="border: 2px solid ${resultColor}; background: ${actualPrediction === 1 ? 'linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%)' : 'linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%)'};margin-top: 1.5rem;">
            <h4 style="color: ${resultColor};">
                <i class="fas ${resultIcon}"></i> Final Decision
                <span class="stage-status stage-completed">
                    <i class="fas fa-check"></i>
                    Complete
                </span>
            </h4>
            <div class="analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Final Prediction:</span>
                    <span class="detail-value" style="color: ${resultColor}; font-weight: bold;">
                        <i class="fas ${resultIcon}"></i>
                        ${result.final_label}
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${confidence}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Analysis Mode:</span>
                    <span class="detail-value">${formatAnalysisMode(result.analysis_mode)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Decision Stage:</span>
                    <span class="detail-value">${result.decision_stage?.replace('_', ' ') || 'Unknown'}</span>
                </div>
            </div>
            <div class="confidence-bar">
                <div class="confidence-level" style="width: ${confidence}%; background: ${resultColor};"></div>
            </div>
            <div style="margin-top: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">
                <strong>Decision Reason:</strong> ${result.decision_reason || 'Analysis completed successfully'}
            </div>
            ${result.total_execution_time ? `<small style="color: #666; margin-top: 0.5rem; display: block;"><i class="fas fa-clock"></i> Total execution time: ${(result.total_execution_time * 1000).toFixed(0)}ms</small>` : ''}
        </div>
    `;
}

// ========================================
// STATUS SECTIONS FOR MAIN.JS
// ========================================

async function initMainStatusSections() {
    const detectionSection = document.querySelector('#detection-section') || document.body;
    
    // Remove existing status containers if they exist
    const existingContainer = document.querySelector('.main-status-wrapper');
    if (existingContainer) {
        existingContainer.remove();
    }
    
    // Create main wrapper for the two-column layout
    const mainWrapper = document.createElement('div');
    mainWrapper.className = 'main-status-wrapper';
    mainWrapper.style.cssText = `
        display: flex;
        gap: 2rem;
        margin: 0 auto 2rem auto;
        max-width: 1200px;
        width: 100%;
    `;
    
    // Create left column container (System Status)
    const leftContainer = document.createElement('div');
    leftContainer.className = 'container';
    leftContainer.style.cssText = `
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
        height: fit-content;
        margin: 0;
    `;
    
    // Create right column container (Detection Feed)
    const rightContainer = document.createElement('div');
    rightContainer.className = 'container';
    rightContainer.style.cssText = `
        flex: 1;
        display: flex;
        flex-direction: column;
        height: 849px;
        margin: 0;
    `;
    
    mainWrapper.appendChild(leftContainer);
    mainWrapper.appendChild(rightContainer);
    detectionSection.appendChild(mainWrapper);
    
    // Populate the sections
    displaySystemStatusSections(leftContainer);
    displayDetectionFeedSection(rightContainer);
}

/**
 * Display system status sections in left column - MODIFIED to use real API data
 */
async function displaySystemStatusSections(leftContainer) {
    // Show loading state first
    leftContainer.innerHTML = `
        <h2 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-server"></i> System Status
        </h2>
        <div class="loading" style="text-align: center; padding: 2rem;">
            <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
            <div>Loading system status...</div>
        </div>
    `;
    
    try {
        // Fetch real API data
        const response = await makeApiRequest(API_ENDPOINTS.MODEL_INFO);
        
        if (response.success && response.data.status === 'success') {
            const statusData = response.data;
            const staticModel = statusData.static_model || {};
            const dynamicModel = statusData.dynamic_model || {};
            const cuckooStatus = statusData.cuckoo_status || { status: 'unknown' };
            
            const staticReady = staticModel.loaded || false;
            const dynamicReady = dynamicModel.loaded || false;
            const cuckooReady = cuckooStatus.status === 'connected';
            
            // Display real status data with same layout
            leftContainer.innerHTML = `
                <h2 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-server"></i> System Status
                </h2>
                
                <!-- Static Analysis Status -->
                <div class="analysis-section" style="margin: 0 0 1.5rem 0; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);">
                    <h4 style="margin: 0 0 1rem 0; display: flex; align-items: center; justify-content: space-between; color: var(--text-main);">
                        <span><i class="fas fa-file-code" style="margin-right: 10px; color: #1976d2;"></i> Static Analysis</span>
                        <span class="stage-status ${staticReady ? 'stage-completed' : 'stage-skipped'}">
                            <i class="fas ${staticReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${staticReady ? 'MODELS READY' : 'MODELS NOT READY'}
                        </span>
                    </h4>
                    <div style="display: grid; gap: 0.75rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${staticReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-tree" style="margin-right: 8px;"></i> Random Forest</span>
                            <span style="color: ${staticReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${staticReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${staticReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${staticReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-vector-square" style="margin-right: 8px;"></i> SVM</span>
                            <span style="color: ${staticReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${staticReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${staticReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${staticReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-rocket" style="margin-right: 8px;"></i> XGBoost</span>
                            <span style="color: ${staticReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${staticReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${staticReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${staticReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-lightbulb" style="margin-right: 8px;"></i> Static XAI</span>
                            <span style="color: ${staticReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${staticReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${staticReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                    </div>
                </div>

                <!-- Dynamic Analysis Status -->
                <div class="analysis-section" style="margin: 0; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);">
                    <h4 style="margin: 0 0 1rem 0; display: flex; align-items: center; justify-content: space-between; color: var(--text-main);">
                        <span><i class="fas fa-play-circle" style="margin-right: 10px; color: #1976d2;"></i> Dynamic Analysis</span>
                        <span class="stage-status ${dynamicReady && cuckooReady ? 'stage-completed' : 'stage-skipped'}">
                            <i class="fas ${dynamicReady && cuckooReady ? 'fa-check-circle' : 'fa-exclamation-triangle'}"></i> ${dynamicReady && cuckooReady ? 'SYSTEM READY' : 'SANDBOX NOT READY'}
                        </span>
                    </h4>
                    <div style="display: grid; gap: 0.75rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${dynamicReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-tree" style="margin-right: 8px;"></i> Random Forest</span>
                            <span style="color: ${dynamicReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${dynamicReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${dynamicReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${dynamicReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-vector-square" style="margin-right: 8px;"></i> SVM</span>
                            <span style="color: ${dynamicReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${dynamicReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${dynamicReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${dynamicReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-rocket" style="margin-right: 8px;"></i> XGBoost</span>
                            <span style="color: ${dynamicReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${dynamicReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${dynamicReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${dynamicReady ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-lightbulb" style="margin-right: 8px;"></i> Dynamic XAI</span>
                            <span style="color: ${dynamicReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${dynamicReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${dynamicReady ? 'Ready' : 'Not Ready'}
                            </span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255, 255, 255, 0.05); border-radius: 6px; border-left: 4px solid ${cuckooReady ? '#28a745' : '#f44336'};">
                            <span><i class="fas fa-cube" style="margin-right: 8px;"></i> Cuckoo Sandbox</span>
                            <span style="color: ${cuckooReady ? '#4caf50' : '#f44336'}; font-weight: 600;">
                                <i class="fas ${cuckooReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${cuckooReady ? 'Connected' : 'Disconnected'}
                            </span>
                        </div>
                    </div>
                </div>
            `;
        } else {
            throw new Error(response.error || 'Failed to get system status');
        }
        
    } catch (error) {
        console.error('System status error:', error);
        leftContainer.innerHTML = `
            <h2 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-server"></i> System Status
            </h2>
            <div style="color: #c62828; padding: 1rem; background: #ffcdd2; border-radius: 8px;">
                <strong><i class="fas fa-wifi"></i> Connection Error:</strong> Cannot connect to analysis API<br>
                <small>Make sure the server is running</small>
            </div>
        `;
    }
}

/**
 * Display detection feed section in right column - MODIFIED to use real API data
 */
async function displayDetectionFeedSection(rightContainer) {
    // Show loading state first
    rightContainer.innerHTML = `
        <h2 style="margin: 0 0 1.5rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-stream"></i> Real-time Detection Feed
        </h2>
        
        <h4 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-list"></i> Recent Detections
        </h4>
        
        <div class="loading" style="text-align: center; padding: 2rem;">
            <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
            <div>Loading recent detections...</div>
        </div>
    `;
    
    try {
        // Fetch real detection data from API
        const response = await makeApiRequest(API_ENDPOINTS.RECENT_RESULTS || '/api/recent-results');
        
        let detections = [];
        
        if (response.success && Array.isArray(response.data)) {
            // Transform database results to UI format
            detections = response.data.map(result => transformDetectionData(result));
        } else {
            console.warn('Failed to fetch recent results:', response.error);
            // Show empty state instead of dummy data
            detections = [];
        }
        
        // Display the feed with real or empty data
        rightContainer.innerHTML = `
            <h2 style="margin: 0 0 1.5rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-stream"></i> Real-time Detection Feed
            </h2>
            
            <h4 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-list"></i> Recent Detections
            </h4>
            
            <!-- Scrollable detection feed area -->
            <div style="
                flex: 1;
                overflow-y: auto;
                padding-right: 8px;
                scrollbar-width: thin;
                scrollbar-color: rgba(255, 255, 255, 0.3) transparent;
            ">
                <!-- Custom scrollbar styles -->
                <style>
                    .container div::-webkit-scrollbar {
                        width: 8px;
                    }
                    .container div::-webkit-scrollbar-track {
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 4px;
                    }
                    .container div::-webkit-scrollbar-thumb {
                        background: rgba(255, 255, 255, 0.3);
                        border-radius: 4px;
                        transition: all 0.3s ease;
                    }
                    .container div::-webkit-scrollbar-thumb:hover {
                        background: rgba(255, 255, 255, 0.5);
                    }
                </style>
                
                ${detections.length > 0 ? detections.map(detection => `
                    <div style="
                        margin-bottom: 1rem; 
                        padding: 1rem; 
                        background: rgba(255, 255, 255, 0.05); 
                        border-radius: 8px; 
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        border-left: 4px solid ${detection.color};
                    ">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                            <div style="display: flex; align-items: center; gap: 10px; flex: 1;">
                                <i class="${detection.icon}" style="color: ${detection.color}; font-size: 1.2rem;"></i>
                                <span style="font-weight: 600; color: var(--text-main);">${detection.filename}</span>
                            </div>
                            <span style="
                                background: ${detection.badgeColor}; 
                                color: white; 
                                padding: 0.2rem 0.6rem; 
                                border-radius: 12px; 
                                font-size: 0.8rem;
                                font-weight: 600;
                                white-space: nowrap;
                                margin-left: 10px;
                            ">
                                ${detection.confidence}
                            </span>
                        </div>
                        <div style="color: var(--text-alt); font-size: 0.9rem; margin-bottom: 0.3rem;">
                            ${detection.result}
                        </div>
                        <div style="color: var(--text-alt); font-size: 0.8rem; opacity: 0.8;">
                            ${detection.timestamp}
                        </div>
                    </div>
                `).join('') : `
                    <div style="
                        text-align: center; 
                        padding: 3rem 1rem; 
                        color: var(--text-alt); 
                        background: rgba(255, 255, 255, 0.02); 
                        border-radius: 8px;
                        border: 1px dashed rgba(255, 255, 255, 0.1);
                    ">
                        <i class="fas fa-inbox" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.3;"></i>
                        <div style="font-size: 1.1rem; margin-bottom: 0.5rem;">No Recent Detections</div>
                        <div style="font-size: 0.9rem; opacity: 0.7;">Analyzed files will appear here in real-time</div>
                    </div>
                `}
            </div>
        `;
        
    } catch (error) {
        console.error('Detection feed error:', error);
        rightContainer.innerHTML = `
            <h2 style="margin: 0 0 1.5rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-stream"></i> Real-time Detection Feed
            </h2>
            
            <h4 style="margin: 0 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-list"></i> Recent Detections
            </h4>
            
            <div style="color: #c62828; padding: 1rem; background: #ffcdd2; border-radius: 8px;">
                <strong><i class="fas fa-exclamation-triangle"></i> Connection Error:</strong> Cannot load recent detections<br>
                <small>Check API connection</small>
            </div>
        `;
    }
}

/**
 * Transform database detection result to UI format
 */
function transformDetectionData(dbResult) {
    const prediction = dbResult.prediction || 0;
    const filename = dbResult.filename || 'Unknown file';
    const createdAt = dbResult.created_at || dbResult.timestamp;
    
    // Extract confidence from analysis_result if available
    let confidence = 'N/A';
    if (dbResult.analysis_result && typeof dbResult.analysis_result === 'object') {
        const analysisResult = dbResult.analysis_result;
        if (analysisResult.confidence) {
            confidence = `${(analysisResult.confidence * 100).toFixed(1)}%`;
        }
    }
    
    // Generate timestamp relative to now
    const timestamp = formatRelativeTime(createdAt);
    
    // Determine result message based on prediction
    let result, icon, color, badgeColor;
    
    if (prediction === 1) {
        // Ransomware detected
        result = 'Ransomware detected - Threat identified';
        icon = 'fas fa-exclamation-triangle';
        color = '#f44336';
        badgeColor = '#f44336';
    } else {
        // Clean file
        result = 'Clean - No threats detected';
        icon = 'fas fa-shield-alt';
        color = '#4caf50';
        badgeColor = '#4caf50';
    }
    
    // Try to get more specific result from analysis_result
    if (dbResult.analysis_result && typeof dbResult.analysis_result === 'object') {
        const analysisResult = dbResult.analysis_result;
        
        // Use final_label if available
        if (analysisResult.final_label) {
            if (prediction === 1) {
                result = `${analysisResult.final_label} detected - Threat identified`;
            } else {
                result = `${analysisResult.final_label} - Verified safe`;
            }
        }
        
        // Add analysis mode information if available
        if (analysisResult.analysis_mode) {
            const modeMap = {
                'signature_only': 'Signature analysis',
                'signature_static': 'Static analysis',
                'full_3_stage': 'Full pipeline analysis'
            };
            const modeText = modeMap[analysisResult.analysis_mode] || 'Analysis completed';
            result = `${result.split(' - ')[0]} - ${modeText}`;
        }
    }
    
    return {
        filename,
        result,
        timestamp,
        confidence,
        icon,
        color,
        badgeColor
    };
}

/**
 * Format timestamp to relative time (e.g., "2 minutes ago")
 */
function formatRelativeTime(timestamp) {
    if (!timestamp) return 'Unknown time';
    
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    
    if (diffMs < 0) return 'Just now';
    
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffSeconds < 60) {
        return diffSeconds <= 1 ? 'Just now' : `${diffSeconds} seconds ago`;
    } else if (diffMinutes < 60) {
        return diffMinutes === 1 ? '1 minute ago' : `${diffMinutes} minutes ago`;
    } else if (diffHours < 24) {
        return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
    } else {
        return diffDays === 1 ? '1 day ago' : `${diffDays} days ago`;
    }
}

// ========================================
// INITIALIZATION AND EVENT HANDLING
// ========================================

/**
 * Initialize main page when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the main detection page (detection-section is active)
    const detectionSection = document.getElementById('detection-section');
    if (detectionSection && detectionSection.classList.contains('active') && mainUploadArea) {
        initializeMainPage();
        initMainStatusSections();
    }
});

// ========================================
// EXPORTS
// ========================================

export {
    initializeMainPage,
    scanMainFiles,
    clearMainFiles,
    displayMainResult,
    displayMainError,
    mainFilesToScan,
    mainScanResults
};

// Add these to make main's internal functions global
window.generateSignatureAnalysisSection = generateSignatureAnalysisSection;
window.generateDynamicAnalysisSection = generateDynamicAnalysisSection;
window.generateFinalDecisionSection = generateFinalDecisionSection;

console.log('✅ main.js loaded - Full 3-Stage Pipeline Ready');