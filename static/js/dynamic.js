// ========================================
// DYNAMIC.JS - Fixed Dynamic Analysis Module
// ========================================
// This file contains all dynamic analysis functionality matching the original script.js behavior

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
    safeGetIndividualModels,
    toggleCollapsibleSection,
    getModelIcon,
    determineActualPrediction
} from './core.js';

// ========================================
// DYNAMIC API ENDPOINTS (Fixed)
// ========================================
// Ori: DYNAMIC_API_ENDPOINTS in original script.js
const DYNAMIC_API_ENDPOINTS = {
    DYNAMIC_ANALYSIS: `${API_ENDPOINTS.API_BASE_URL || ''}/api/dynamic-analysis`,
    DYNAMIC_STATUS: `${API_ENDPOINTS.API_BASE_URL || ''}/api/dynamic-status`,
    CUCKOO_STATUS: `${API_ENDPOINTS.API_BASE_URL || ''}/api/cuckoo-status`,
};

// ========================================
// DYNAMIC-SPECIFIC VARIABLES
// ========================================
// Ori: Same variable names as original script.js
let dynamicFilesToScan = [];
let dynamicScanResults = [];
let dynamicTestFile = null;

// ========================================
// DOM ELEMENTS (Fixed - Direct Assignment)
// ========================================
// Ori: Direct getElementById calls in original script.js
const dynamicUploadArea = document.getElementById('dynamic-upload-area');
const dynamicFileInput = document.getElementById('dynamic-file-input');
const dynamicFileListContainer = document.getElementById('dynamic-file-list-container');
const dynamicFileList = document.getElementById('dynamic-file-list');
const dynamicScanButton = document.getElementById('dynamic-scan-button');
const dynamicClearButton = document.getElementById('dynamic-clear-button');
const dynamicLoading = document.getElementById('dynamic-loading');
const dynamicLoadingText = document.getElementById('dynamic-loading-text');
const dynamicProgressBar = document.getElementById('dynamic-progress-fill');
const dynamicCurrentFile = document.getElementById('dynamic-current-file');
const dynamicCurrentStage = document.getElementById('dynamic-current-stage');
const dynamicStageDescription = document.getElementById('dynamic-stage-description');
const dynamicResultsContainer = document.getElementById('dynamic-results-container');
const dynamicResultsArea = document.getElementById('dynamic-results-area');
const dynamicTotalAnalyzed = document.getElementById('dynamic-total-analyzed');
const dynamicSafeCount = document.getElementById('dynamic-safe-count');
const dynamicThreatCount = document.getElementById('dynamic-threat-count');
const dynamicEnsembleCount = document.getElementById('dynamic-ensemble-count');
const dynamicSystemStatus = document.getElementById('dynamic-system-status');
const dynamicStatusContent = document.getElementById('dynamic-status-content');

// ========================================
// CORE DYNAMIC FUNCTIONS
// ========================================

/**
 * Initialize dynamic analysis page
 * Ori: initializeDynamicAnalysis() in original script.js
 */
function initDynamicAnalysisPage() {
    console.log('🔥 Initializing Dynamic Analysis Page...');
    
    if (!dynamicUploadArea) {
        console.log('Dynamic upload area not found, skipping initialization');
        return;
    }
    
    // Setup file upload functionality
    setupDynamicFileUpload();
    
    // Setup button event listeners
    setupDynamicEventListeners();
    
    // Check dynamic system status
    checkDynamicAnalysisSystemStatus();
    
    console.log('✅ Dynamic Analysis Page initialized');
}

/**
 * Setup dynamic file upload functionality
 * Ori: Part of initializeDynamicAnalysis() in original script.js
 */
function setupDynamicFileUpload() {
    if (dynamicUploadArea && dynamicFileInput) {
        // Use centralized setup from core.js instead of manual setup
        setupFileInput(dynamicUploadArea, dynamicFileInput, handleDynamicFileSelection);
        setupDragAndDrop(dynamicUploadArea, handleDynamicFileSelection);
        
        console.log('✅ Dynamic file upload setup complete');
    }
}

/**
 * Setup dynamic event listeners
 * Ori: Part of initializeDynamicAnalysis() in original script.js
 */
function setupDynamicEventListeners() {
    if (dynamicScanButton) {
        dynamicScanButton.addEventListener('click', scanDynamicAnalysisFiles);
    }
    
    if (dynamicClearButton) {
        dynamicClearButton.addEventListener('click', clearDynamicAnalysisFiles);
    }
}

/**
 * Check dynamic analysis system status
 * Ori: Part of dynamic system status check in original script.js
 */
async function checkDynamicAnalysisSystemStatus() {
    if (!dynamicStatusContent) {
        console.log('Dynamic status content element not found');
        return;
    }
    
    try {
        dynamicStatusContent.innerHTML = `
            <div class="loading">
                <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
                <div>  Checking dynamic analysis system...</div>
            </div>
        `;

        // Use the MODEL_INFO endpoint to get dynamic model status
        const response = await makeApiRequest(API_ENDPOINTS.MODEL_INFO);

        if (response.success && response.data.status === 'success') {
            const dynamicModel = response.data.dynamic_model || {};
            const cuckooStatus = response.data.cuckoo_status || { status: 'unknown' };
            
            displayDynamicAnalysisSystemStatus(dynamicModel, cuckooStatus);
        } else {
            throw new Error(response.error || 'Failed to get model info');
        }

    } catch (error) {
        console.error('Dynamic system status check error:', error);
        dynamicStatusContent.innerHTML = `
            <div style="color: #c62828; padding: 1rem; background: #ffcdd2; border-radius: 8px;">
                <strong><i class="fas fa-wifi"></i> Connection Error:</strong> Cannot connect to dynamic analysis API<br>
                <small>Make sure the server is running</small>
            </div>
        `;
        disableDynamicAnalysisUpload();
    }
}

/**
 * Display dynamic analysis system status
 * Ori: New function based on original system status display logic
 */
function displayDynamicAnalysisSystemStatus(dynamicModel, cuckooStatus) {
    if (!dynamicStatusContent) return;
    
    const dynamicReady = dynamicModel.loaded || false;
    const cuckooReady = cuckooStatus.status === 'connected';
    const ensembleAvailable = dynamicModel.ensemble_available || false;
    const xaiAvailable = dynamicModel.xai_loaded || false;
    const models = dynamicModel.individual_models || {};

    dynamicStatusContent.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
            <!-- Dynamic Models Section -->
            <div style="padding: 1.5rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 12px; border: 1px solid #dee2e6;">
                <h3 style="margin: 0 0 1rem 0; color: #495057; display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-brain" style="color: #6c757d;"></i>
                    Dynamic Analysis Models
                </h3>
                <div style="display: grid; gap: 0.75rem;">
                    ${Object.entries(models).map(([name, info]) => `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${info.loaded ? '#28a745' : '#dc3545'};">
                            <span><i class="fas fa-${getModelIcon(name)}"></i> ${name.toLowerCase() === 'randomforest' ? 'Random Forest' : name.toLowerCase() === 'svm' ? 'SVM' : name.toLowerCase() === 'xgboost' ? 'XGBoost' : name.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                            <span style="color: ${info.loaded ? '#28a745' : '#dc3545'}; font-weight: 600;">
                                <i class="fas ${info.loaded ? 'fa-check-circle' : 'fa-times-circle'}"></i> 
                                ${info.loaded ? 'Ready' : 'Not Loaded'}
                            </span>
                        </div>
                    `).join('')}
                </div>
                <div style="margin-top: 1rem; padding: 0.75rem; background: ${dynamicReady ? '#d4edda' : '#f8d7da'}; border-radius: 6px; text-align: center;">
                    <strong style="color: ${dynamicReady ? '#155724' : '#721c24'};">
                        ${dynamicReady ? '✅ Models Ready' : '❌ Models Not Ready'}
                    </strong>
                </div>
            </div>

            <!-- Cuckoo Sandbox Section -->
            <div style="padding: 1.5rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 12px; border: 1px solid #dee2e6;">
                <h3 style="margin: 0 0 1rem 0; color: #495057; display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-cube" style="color: #6c757d;"></i>
                    Cuckoo Sandbox
                </h3>
                <div style="display: grid; gap: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${cuckooReady ? '#28a745' : '#dc3545'};">
                        <span><i class="fas fa-server"></i> Sandbox Connection</span>
                        <span style="color: ${cuckooReady ? '#28a745' : '#dc3545'}; font-weight: 600;">
                            <i class="fas ${cuckooReady ? 'fa-check-circle' : 'fa-times-circle'}"></i> 
                            ${cuckooReady ? 'Connected' : 'Disconnected'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${ensembleAvailable ? '#28a745' : '#ffc107'};">
                        <span><i class="fas fa-vote-yea"></i> Ensemble Analysis</span>
                        <span style="color: ${ensembleAvailable ? '#28a745' : '#856404'}; font-weight: 600;">
                            <i class="fas ${ensembleAvailable ? 'fa-check-circle' : 'fa-clock'}"></i> 
                            ${ensembleAvailable ? 'Available' : 'Single Model'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border-left: 4px solid ${xaiAvailable ? '#28a745' : '#ffc107'};">
                        <span><i class="fas fa-lightbulb"></i> XAI Explanations</span>
                        <span style="color: ${xaiAvailable ? '#28a745' : '#856404'}; font-weight: 600;">
                            <i class="fas ${xaiAvailable ? 'fa-check-circle' : 'fa-clock'}"></i> 
                            ${xaiAvailable ? 'Ready' : 'Loading'}
                        </span>
                    </div>
                </div>
                <div style="margin-top: 1rem; padding: 0.75rem; background: ${cuckooReady ? '#d4edda' : '#f8d7da'}; border-radius: 6px; text-align: center;">
                    <strong style="color: ${cuckooReady ? '#155724' : '#721c24'};">
                        ${cuckooReady ? '✅ Sandbox Ready' : '❌ Sandbox Not Ready'}
                    </strong>
                </div>
            </div>
        </div>
        
        <div style="margin-top: 1.5rem; padding: 1rem; background: ${dynamicReady && cuckooReady ? '#e3f2fd' : '#fff3cd'}; border-radius: 8px; color: ${dynamicReady && cuckooReady ? '#1565c0' : '#856404'}; border-left: 4px solid ${dynamicReady && cuckooReady ? '#2196f3' : '#ffc107'};">
            <strong><i class="fas fa-info-circle"></i> System Status:</strong> 
            ${dynamicReady && cuckooReady ? 'Full dynamic analysis with ensemble ML and XAI explanations available' : 
              dynamicReady ? 'Dynamic models ready but Cuckoo sandbox unavailable' :
              cuckooReady ? 'Cuckoo sandbox ready but dynamic models unavailable' :
              'Dynamic analysis system not available'}
        </div>
    `;

    // Enable/disable upload based on system status
    if (!dynamicReady || !cuckooReady) {
        disableDynamicAnalysisUpload();
    } else {
        enableDynamicAnalysisUpload();
    }
}

/**
 * Disable dynamic upload interface
 * Ori: New function based on original logic
 */
function disableDynamicAnalysisUpload() {
    if (dynamicUploadArea) {
        dynamicUploadArea.style.pointerEvents = 'none';
        dynamicUploadArea.style.opacity = '0.6';
    }
}

/**
 * Enable dynamic upload interface
 * Ori: New function based on original logic
 */
function enableDynamicAnalysisUpload() {
    if (dynamicUploadArea) {
        dynamicUploadArea.style.pointerEvents = 'auto';
        dynamicUploadArea.style.opacity = '1';
    }
}

// ========================================
// DYNAMIC FILE HANDLING FUNCTIONS
// ========================================

/**
 * Handle dynamic file input change
 * Ori: handleDynamicFileSelection() in original script.js
 */
function handleDynamicFileInputChange(event) {
    handleDynamicFileSelection(event.target.files);
}

/**
 * Process dynamic files for upload
 * Ori: handleDynamicFileSelection() in original script.js
 */
function handleDynamicFileSelection(fileList) {
    const validFiles = [];
    
    for (let file of fileList) {
        const validation = validateFile(file);
        
        if (!validation.success) {
            showNotification(validation.message, 'error');
            continue;
        }
        
        // Check if file already exists
        const isDuplicate = dynamicFilesToScan.some(f => 
            f.name === file.name && f.size === file.size
        );
        
        if (!isDuplicate) {
            validFiles.push(file);
        }
    }
    
    // Add valid files to the list
    dynamicFilesToScan.push(...validFiles);
    
    // Update the file list display
    updateDynamicAnalysisFileList();
    
    // Show success notification if files were added
    if (validFiles.length > 0) {
        showNotification(`${validFiles.length} file(s) added for dynamic analysis`, 'success');
    }
}

/**
 * Update the dynamic file list display
 * Ori: updateDynamicFileList() in original script.js
 */
function updateDynamicAnalysisFileList() {
    if (!dynamicFileListContainer || !dynamicFileList) return;
    
    if (dynamicFilesToScan.length > 0) {
        dynamicFileListContainer.style.display = 'block';
        dynamicFileList.innerHTML = '';
        
        dynamicFilesToScan.forEach((file, index) => {
            const li = document.createElement('li');
            li.className = 'file-item';
            
            const nameSpan = document.createElement('span');
            nameSpan.className = 'file-name';
            nameSpan.textContent = `${file.name} (${formatFileSize(file.size)})`;
            
            const removeButton = document.createElement('button');
            removeButton.innerHTML = '<i class="fas fa-trash"></i> Remove';
            removeButton.className = 'btn-secondary';
            removeButton.style.fontSize = '0.8rem';
            removeButton.style.padding = '5px 10px';
            removeButton.addEventListener('click', () => removeDynamicAnalysisFile(index));
            
            li.appendChild(nameSpan);
            li.appendChild(removeButton);
            dynamicFileList.appendChild(li);
        });
    } else {
        dynamicFileListContainer.style.display = 'none';
    }
}

/**
 * Remove a file from the dynamic files list
 * Ori: Part of updateDynamicFileList() logic in original script.js
 */
function removeDynamicAnalysisFile(index) {
    if (index >= 0 && index < dynamicFilesToScan.length) {
        const removedFile = dynamicFilesToScan.splice(index, 1)[0];
        updateDynamicAnalysisFileList();
        showNotification(`${removedFile.name} removed from dynamic analysis`, 'info');
    }
}

/**
 * Clear all dynamic files
 * Ori: clearDynamicFiles() in original script.js
 */
function clearDynamicAnalysisFiles() {
    dynamicFilesToScan = [];
    updateDynamicAnalysisFileList();
    hideDynamicAnalysisResults();
    showNotification('All files cleared from dynamic analysis', 'info');
}

/**
 * Hide dynamic results container
 * Ori: Part of clearDynamicFiles() in original script.js
 */
function hideDynamicAnalysisResults() {
    if (dynamicResultsContainer) {
        dynamicResultsContainer.style.display = 'none';
    }
    if (dynamicResultsArea) {
        dynamicResultsArea.innerHTML = '';
    }
}

// ========================================
// DYNAMIC SCANNING FUNCTIONS
// ========================================

/**
 * Scan all dynamic files
 * Ori: scanDynamicFiles() in original script.js
 */
async function scanDynamicAnalysisFiles() {
    if (dynamicFilesToScan.length === 0) {
        showNotification('No files selected for dynamic analysis', 'error');
        return;
    }
    
    // Show loading and disable buttons
    showDynamicAnalysisLoading(true);
    
    // Clear previous results
    dynamicScanResults = [];
    clearDynamicAnalysisResultsArea();
    
    let safeCnt = 0;
    let threatCnt = 0;
    let ensembleCnt = 0;
    
    console.log(`🔥 Starting dynamic analysis for ${dynamicFilesToScan.length} files...`);
    
    for (let i = 0; i < dynamicFilesToScan.length; i++) {
        const file = dynamicFilesToScan[i];
        
        try {
            // Update progress
            updateDynamicAnalysisProgress(i + 1, dynamicFilesToScan.length, file.name, 'cuckoo_submit');
            
            // Perform dynamic analysis
            const result = await performDynamicFileAnalysis(file);
            
            if (result.success) {
                dynamicScanResults.push(result.data);
                displayDynamicAnalysisResult(file.name, result.data);
                
                // Update counters
                if (result.data.prediction === 1) {
                    threatCnt++;
                } else {
                    safeCnt++;
                }
                
                // Count ensemble analyses
                if (result.data.ensemble_details && result.data.ensemble_details.analysis_type === 'ensemble') {
                    ensembleCnt++;
                }
            } else {
                displayDynamicAnalysisError(file.name, result.error);
            }
            
        } catch (error) {
            console.error(`Dynamic analysis error for ${file.name}:`, error);
            displayDynamicAnalysisError(file.name, error.message);
        }
    }
    
    // Update final statistics
    updateDynamicAnalysisStats(safeCnt, threatCnt, ensembleCnt);
    
    // Show results and hide loading
    showDynamicAnalysisResults();
    showDynamicAnalysisLoading(false);
    
    // Show completion notification
    const totalFiles = safeCnt + threatCnt;
    showNotification(`Dynamic analysis complete! ${totalFiles} files processed, ${threatCnt} threats detected.`, 'success');
}

/**
 * Perform dynamic analysis on a single file
 * Ori: Part of scanDynamicFiles() in original script.js
 */
async function performDynamicFileAnalysis(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    return await makeApiRequest(DYNAMIC_API_ENDPOINTS.DYNAMIC_ANALYSIS, {
        method: 'POST',
        body: formData
    });
}

// ========================================
// DYNAMIC UI FUNCTIONS
// ========================================

/**
 * Show/hide dynamic loading screen
 * Ori: Dynamic loading control in original script.js
 */
function showDynamicAnalysisLoading(show) {
    if (dynamicLoading) {
        dynamicLoading.style.display = show ? 'flex' : 'none';
    }
    
    if (dynamicScanButton) {
        dynamicScanButton.disabled = show;
    }
    
    if (dynamicClearButton) {
        dynamicClearButton.disabled = show;
    }
}

/**
 * Update dynamic analysis progress
 * Ori: updateDynamicProgress() in original script.js
 */
function updateDynamicAnalysisProgress(current, total, fileName, stage) {
    const progress = (current / total) * 100;
    
    if (dynamicProgressBar) {
        dynamicProgressBar.style.width = `${progress}%`;
    }
    
    if (dynamicCurrentFile) {
        dynamicCurrentFile.innerHTML = `<i class="fas fa-file"></i> Analyzing: ${fileName}`;
    }
    
    // Stage information
    const stageInfo = {
        'cuckoo_submit': {
            text: 'Submitting to Cuckoo Sandbox',
            description: 'Uploading file to sandbox environment',
            icon: 'fa-upload'
        },
        'cuckoo_analysis': {
            text: 'Cuckoo Behavioral Analysis',
            description: 'File execution and behavior monitoring (3-5 minutes)',
            icon: 'fa-cube'
        },
        'ensemble_analysis': {
            text: 'Ensemble ML Analysis',
            description: 'Processing with SVM + Random Forest + XGBoost',
            icon: 'fa-brain'
        },
        'xai_explanation': {
            text: 'XAI Feature Explanation',
            description: 'Generating feature importance and explanations',
            icon: 'fa-lightbulb'
        }
    };
    
    const currentStageInfo = stageInfo[stage] || {
        text: 'Processing',
        description: 'Analyzing file...',
        icon: 'fa-cog'
    };
    
    if (dynamicLoadingText) {
        dynamicLoadingText.innerHTML = `<i class="fas ${currentStageInfo.icon}"></i> ${currentStageInfo.text} (${current}/${total})<br><br>`;
    }
    
    if (dynamicCurrentStage) {
        dynamicCurrentStage.innerHTML = `<i class="fas ${currentStageInfo.icon}"></i> ${currentStageInfo.text}`;
    }
    
    if (dynamicStageDescription) {
        dynamicStageDescription.textContent = currentStageInfo.description;
    }
}

/**
 * Update dynamic statistics display
 * Ori: Stats update in original script.js
 */
function updateDynamicAnalysisStats(safeCount, threatCount, ensembleCount) {
    const totalCount = safeCount + threatCount;
    
    if (dynamicTotalAnalyzed) {
        dynamicTotalAnalyzed.textContent = totalCount;
    }
    if (dynamicSafeCount) {
        dynamicSafeCount.textContent = safeCount;
    }
    if (dynamicThreatCount) {
        dynamicThreatCount.textContent = threatCount;
    }
    if (dynamicEnsembleCount) {
        dynamicEnsembleCount.textContent = ensembleCount;
    }
}

/**
 * Show dynamic results container
 * Ori: Results display in original script.js
 */
function showDynamicAnalysisResults() {
    if (dynamicResultsContainer) {
        dynamicResultsContainer.style.display = 'block';
    }
}

/**
 * Clear dynamic results area
 * Ori: Results clearing in original script.js
 */
function clearDynamicAnalysisResultsArea() {
    if (dynamicResultsArea) {
        dynamicResultsArea.innerHTML = '';
    }
}

// ========================================
// DYNAMIC RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Display dynamic analysis result
 * Ori: displayDynamicResult() in original script.js (renamed from displayDynamicBatchResult)
 */
function displayDynamicAnalysisResult(fileName, result) {
    if (!dynamicResultsArea) return;
    
    const resultCard = document.createElement('div');

    resultCard.className = 'result-card';

    let predictionValue = determineActualPrediction(result);

    const confidence = (result.confidence * 100).toFixed(1);
    const analysisType = result.analysis_type || 'single_model';
    const badgeClass = predictionValue === 0 ? 'result-safe' : 'result-threat';
    const badgeIcon = predictionValue === 0 ? 'fa-shield-alt' : 'fa-exclamation-triangle';
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3>${fileName}</h3>
            <div class="result-badge ${badgeClass}">
                <i class="fas ${badgeIcon}"></i>
                ${result.prediction === 1 ? 'Ransomware' : 'Benign'} (${confidence}%)
            </div>
        </div>
        <div class="result-body">
            <div class="analysis-section">
                <h4>
                    <i class="fas ${analysisType === 'ensemble' ? 'fa-brain' : 'fa-play-circle'}"></i> 
                    Dynamic Analysis ${analysisType === 'ensemble' ? '(Ensemble ML)' : '(Behavioral)'}
                    <span class="stage-status stage-completed">
                        <i class="fas fa-check"></i>
                        Completed
                    </span>
                </h4>
                <div class="analysis-details">
                    <div class="detail-item">
                        <span class="detail-label">Prediction:</span>
                        <span class="detail-value">
                            <i class="fas ${predictionValue === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt'}"></i>
                            ${result.prediction === 1 ? 'Ransomware' : 'Benign'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Confidence:</span>
                        <span class="detail-value">${confidence}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Benign Probability:</span>
                        <span class="detail-value">${(result.probabilities.benign * 100).toFixed(1)}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Ransomware Probability:</span>
                        <span class="detail-value">${(result.probabilities.ransomware * 100).toFixed(1)}%</span>
                    </div>
                </div>
                <div class="confidence-bar">    
                    <div class="confidence-level" style="width: ${confidence}%; background: ${predictionValue === 1 ? '#f44336' : '#4caf50'};"></div>
                </div>
                ${generateDynamicEnsembleDetailsSection(result.ensemble_details)}
                ${generateDynamicXAIExplanationSection(result.explanation, result.ensemble_details)}
            </div>
        </div>
    `;
    
    dynamicResultsArea.appendChild(resultCard);
}

/**
 * Display dynamic analysis error
 * Ori: Dynamic error display in original script.js
 */
function displayDynamicAnalysisError(fileName, errorMessage) {
    if (!dynamicResultsArea) return;
    
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
            <div class="analysis-section" style="border-color: #f44336;">
                <h4>
                    <i class="fas fa-exclamation-triangle"></i> Dynamic Analysis Error
                    <span class="stage-status stage-failed">
                        <i class="fas fa-times"></i>
                        Failed
                    </span>
                </h4>
                <div style="background: #ffcdd2; padding: 1rem; border-radius: 8px; color: #c62828;">
                    <strong><i class="fas fa-bug"></i> Error Details:</strong><br>
                    ${errorMessage}
                </div>
                <p style="color: #666; margin-top: 1rem; font-style: italic;">
                    <i class="fas fa-info-circle"></i>
                    The file could not be analyzed dynamically. This may be due to Cuckoo sandbox issues or file format compatibility.
                </p>
            </div>
        </div>
    `;
    
    dynamicResultsArea.appendChild(resultCard);
}

// ========================================
// DYNAMIC RESULT GENERATION FUNCTIONS
// ========================================

/**
 * Generate dynamic ensemble voting details section (FIXED)
 * @param {Object} ensembleDetails - Ensemble details from API
 * @returns {string} HTML string for ensemble details
 */
function generateDynamicEnsembleDetailsSection(ensembleDetails) {
    if (!ensembleDetails || ensembleDetails.analysis_type !== 'ensemble') {
        return `
            <div class="ensemble-section">
                <h5>
                    <i class="fas fa-cog"></i> Single Model Analysis
                    <span class="stage-status stage-completed">
                        <i class="fas fa-check"></i>
                        Completed
                    </span>
                </h5>
                <p style="color: #666; font-style: italic;">
                    <i class="fas fa-info-circle"></i>
                    Analysis performed using single dynamic model.
                </p>
            </div>
        `;
    }
    
    // FIX: Use ensembleDetails.individual_models, not explanation.individual_models
    const individualModels = ensembleDetails.individual_models || {};
    
    let content = `
        <div class="ensemble-section">
            <h5><i class="fas fa-vote-yea"></i> Dynamic Ensemble Voting Results</h5>
            <div class="voting-summary">
    `;
    
    // Display individual model votes
    Object.entries(individualModels).forEach(([modelName, modelData]) => {
        // Convert prediction string to display label
        const predictionLabel = modelData.prediction === 'ransomware' ? 'Ransomware' : 
                            modelData.prediction === 'benign' ? 'Benign' : 
                            modelData.prediction === 1 ? 'Ransomware' : 'Benign';
        
        const isRansomware = (modelData.prediction === 'ransomware' || modelData.prediction === 1);
        const voteClass = isRansomware ? 'vote-threat' : 'vote-safe';
        const voteIcon = isRansomware ? 'fa-exclamation-triangle' : 'fa-shield-alt';
        
        content += `
            <div class="model-vote">
                <div class="model-name">${modelName.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                <div class="vote-result ${voteClass}">
                    <i class="fas ${voteIcon}"></i>
                    ${predictionLabel}
                </div>
                <div class="vote-confidence">${(modelData.confidence * 100).toFixed(1)}%</div>
            </div>
        `;
    });

    content += `</div>`;
    
    // ADD VOTING SUMMARY HERE:
    let ransomwareVotes = 0;
    let benignVotes = 0;

    Object.values(individualModels).forEach(modelData => {
        if (modelData.prediction === 'ransomware' || modelData.prediction === 1) {
            ransomwareVotes++;
        } else {
            benignVotes++;
        }
    });

    content += `
        <div style="margin-top: 1rem; padding: 1rem; background: white; border-radius: 8px; border: 1px solid #e0e0e0;">
            <strong><i class="fas fa-chart-bar"></i> Voting Summary:</strong>
            <span style="margin-left: 1rem;">
                <i class="fas fa-exclamation-triangle" style="color: #f44336;"></i> Ransomware: ${ransomwareVotes}
                <span style="margin-left: 1rem;">
                    <i class="fas fa-shield-alt" style="color: #4caf50;"></i> Benign: ${benignVotes}
                </span>
            </span>
        </div>
    `;

    content += `</div>`;
    return content;
}

/**
 * Generate dynamic XAI explanation section (FIXED)
 * @param {Object} explanation - XAI explanation data
 * @returns {string} HTML string for XAI explanation
 */
function generateDynamicXAIExplanationSection(explanation, ensembleDetails) {
    if (!explanation) {
        return `
            <div class="xai-section">
                <h5><i class="fas fa-brain"></i> XAI Feature Explanation</h5>
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; color: #856404;">
                    <i class="fas fa-info-circle"></i> 
                    XAI explanation data not provided by the dynamic analysis endpoint.
                </div>
            </div>
        `;
    }
    
    if (explanation.available === false) {
        return `
            <div class="xai-section">
                <h5><i class="fas fa-brain"></i> XAI Feature Explanation</h5>
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; color: #856404;">
                    <i class="fas fa-info-circle"></i> 
                    ${explanation?.error || explanation?.reason || 'XAI explanation not available for this analysis.'}
                </div>
            </div>
        `;
    }
    
    // FIX: Use explanation.top_features directly (from your JSON structure)
    // const topFeatures = explanation.top_features || [];
    // const explanationText = explanation.explanation_text || 'Behavioral pattern analysis completed.';
    let topFeatures = [];
    let explanationText = 'Behavioral pattern analysis completed.';
    let individualModels = {};

    // Main pipeline format (nested structure)
    if (explanation.ensemble_explanation) {
        topFeatures = explanation.ensemble_explanation.top_features || [];
        explanationText = explanation.ensemble_explanation.explanation_text || explanationText;
        individualModels = explanation.model_explanations || {};
    }
    
    // Individual dynamic format (direct structure)  
    else if (explanation.top_features) {
        topFeatures = explanation.top_features || [];
        explanationText = explanation.explanation_text || explanationText;
        individualModels = explanation.individual_models || {};
    }

    let content = `
        <div class="xai-section">
            <h5><i class="fas fa-brain"></i> XAI Feature Explanation</h5>
            <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 4px solid #ff9800;">
                <strong><i class="fas fa-lightbulb"></i> Dynamic Feature Analysis:</strong><br>
                <em>${explanationText}</em>
            </div>
    `;
    
    if (topFeatures && topFeatures.length > 0) {
        content += `
            <div>
                <strong><i class="fas fa-list-ol"></i> Top Contributing Dynamic Features:</strong>
                <div style="margin-top: 0.5rem;">
        `;
        
        const initialFeatures = topFeatures.slice(0, 5);
        const remainingFeatures = topFeatures.slice(5);
        const uniqueId = 'dynamic-features-' + Math.random().toString(36).substr(2, 9);
        
        initialFeatures.forEach((feature) => {
            // FIX: Use avg_shap_value for ensemble top features AND contribution field consistently
            const impactClass = feature.contribution === 'positive' ? 'impact-positive' : 'impact-negative';
            const impactIcon = feature.contribution === 'positive' ? 'fa-arrow-up' : 'fa-arrow-down';
            const impactText = feature.contribution === 'positive' ? 'Increases Ransomware Risk' : 'Decreases Ransomware Risk';
            
            content += `
                <div class="feature-contribution">
                    <span class="feature-name">${feature.feature_name || `Behavior ${feature.feature_id}`}</span>
                    <span class="feature-impact ${impactClass}">
                        <i class="fas ${impactIcon}"></i>
                        ${Math.abs(feature.avg_shap_value || 0).toFixed(3)} (${impactText})
                    </span>
                </div>
            `;
        });
        
        if (remainingFeatures.length > 0) {
            content += `
                <div id="${uniqueId}-hidden" style="display: none;">
            `;
            
            remainingFeatures.forEach((feature) => {
                // FIX: Use avg_shap_value consistently for ensemble features
                const impactClass = feature.contribution === 'positive' ? 'impact-positive' : 'impact-negative';
                const impactIcon = feature.contribution === 'positive' ? 'fa-arrow-up' : 'fa-arrow-down';
                const impactText = feature.contribution === 'positive' ? 'Increases Ransomware Risk' : 'Decreases Ransomware Risk';
                const featureName = feature.feature_name || feature.name || `Feature ${feature.feature_id || 'Unknown'}`;
                
                content += `
                    <div class="feature-contribution">
                        <span class="feature-name">${featureName}</span>
                        <span class="feature-impact ${impactClass}">
                            <i class="fas ${impactIcon}"></i>
                            ${Math.abs(feature.avg_shap_value || 0).toFixed(3)} (${impactText})
                        </span>
                    </div>
                `;
            });
            
            content += `</div>`;
            
            content += `
                <div style="text-align: right; margin-top: 0.5rem;">
                    <span id="${uniqueId}-toggle" onclick="toggleDynamicAnalysisFeatures('${uniqueId}')" 
                        style="color: #666; font-size: 0.9rem; cursor: pointer; text-decoration: underline;">
                        Show ${remainingFeatures.length} more features...
                    </span>
                </div>
            `;
        }
        
        content += `</div></div>`;
    } else {
        content += `
            <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; color: #856404;">
                <i class="fas fa-info-circle"></i> No feature contributions found in explanation data.
            </div>
        `;
    }
    
    // Add individual model explanations if available
    if (individualModels && Object.keys(individualModels || {}).length > 0) {
        const individualModelsCount = Object.keys(individualModels).length;  // ✅ Use the correct variable
        
        content += `
            <div style="margin-top: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                <div class="individual-models-header" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border: 1px solid #e0e0e0;" onclick="toggleIndividualModels(this)">
                    <strong><i class="fas fa-microscope"></i> Individual Dynamic Model Explanations (${individualModelsCount} models)</strong>
                    <i class="fas fa-chevron-down toggle-icon" style="transition: transform 0.3s ease;"></i>
                </div>
                <div class="individual-models-content" style="display: none; margin-top: 1rem;">
        `;
        
        Object.entries(individualModels).forEach(([modelName, modelData]) => {
            if (!modelData.error && modelData.feature_contributions) {
                const nameMapping = {
                    'randomforest': 'Random Forest',
                    'xgboost': 'XGBoost',
                    'svm': 'SVM'
                };
                const modelDisplayName = nameMapping[modelName] || modelName;
                
                // FIX: Get prediction and confidence from ensemble details
                const ensembleModelData = ensembleDetails?.individual_models?.[modelName] || {};
                
                const confidencePercent = ensembleModelData.confidence ? (ensembleModelData.confidence * 100).toFixed(1) : '0.0';
                const isRansomware = ensembleModelData.prediction === 'ransomware' || ensembleModelData.prediction === 1;
                const borderColor = isRansomware ? '#e74c3c' : '#27ae60';
                const textColor = isRansomware ? '#e74c3c' : '#27ae60';
                const predictionIcon = isRansomware ? 'fa-exclamation-triangle' : 'fa-shield-alt';
                const predictionLabel = isRansomware ? 'Ransomware' : 'Benign';
                
                content += `
                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 4px solid ${borderColor}; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                            <h6 style="margin: 0; font-size: 1rem; font-weight: 600;">
                                <i class="fas fa-brain" style="margin-right: 8px; color: ${borderColor};"></i>
                                ${modelDisplayName}
                            </h6>
                            <div style="text-align: right;">
                                <span style="color: ${textColor}; font-weight: bold; font-size: 0.9rem;">
                                    <i class="fas ${predictionIcon}"></i> ${predictionLabel}
                                </span>
                                <div style="font-size: 0.8rem; color: #666; margin-top: 2px;">
                                    Confidence: ${confidencePercent}%
                                </div>
                            </div>
                        </div>
                        
                        <div style="border-top: 1px solid #f0f0f0; padding-top: 0.75rem;">
                            <strong style="font-size: 0.9rem; color: #555; margin-bottom: 0.5rem; display: block;">
                                <i class="fas fa-list-ol" style="margin-right: 5px;"></i> Top Features:
                            </strong>
                            <div style="display: grid; gap: 0.4rem;">
                `;
                
                // Features section stays the same
                modelData.feature_contributions.slice(0, 3).forEach((feature) => {
                    const impact = feature.contribution === 'positive' ? 'Increases Risk' : 'Decreases Risk';
                    const icon = feature.contribution === 'positive' ? '📈' : '📉';
                    const impactColor = feature.contribution === 'positive' ? '#e74c3c' : '#27ae60';
                    const featureName = feature.feature_name && feature.feature_name.length > 50 ? 
                        feature.feature_name.substring(0, 50) + '...' : feature.feature_name;
                    
                    content += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: #f8f9fa; border-radius: 4px; border-left: 3px solid ${impactColor};">
                            <div style="flex: 1;">
                                <span style="font-weight: 500; font-size: 0.85rem;">${icon} ${featureName}</span>
                            </div>
                            <div style="text-align: right; margin-left: 10px;">
                                <div style="font-weight: bold; color: ${impactColor}; font-size: 0.85rem;">
                                    ${Math.abs(feature.shap_value).toFixed(4)}
                                </div>
                                <div style="font-size: 0.7rem; color: #666;">
                                    ${impact}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                content += `
                            </div>
                        </div>
                    </div>
                `;
            }
        });
        
        content += `
                </div>
            </div>
        `;
    }

    content += `</div>`;
    return content;
}

// ========================================
// DYNAMIC HELPER FUNCTIONS
// ========================================

/**
 * Toggle dynamic features display
 * Ori: toggleDynamicFeatures() in original script.js
 */
function toggleDynamicAnalysisFeatures(uniqueId) {
    const hiddenSection = document.getElementById(`${uniqueId}-hidden`);
    const toggleButton = document.getElementById(`${uniqueId}-toggle`);
    
    if (hiddenSection && toggleButton) {
        if (hiddenSection.style.display === 'none') {
            hiddenSection.style.display = 'block';
            toggleButton.textContent = 'Show less...';
        } else {
            hiddenSection.style.display = 'none';
            const remainingCount = hiddenSection.children.length;
            toggleButton.textContent = `Show ${remainingCount} more features...`;
        }
    }
}

/**
 * Toggle individual models dropdown
 * Ori: toggleIndividualModels() in original script.js
 */
function toggleDynamicAnalysisIndividualModels(headerElement) {
    toggleCollapsibleSection(headerElement);
}

// ========================================
// DYNAMIC TEST UPLOAD FUNCTIONS (Optional)
// ========================================

/**
 * Setup dynamic test upload functionality
 * Ori: Dynamic test functionality in original script.js
 */
function setupDynamicAnalysisTestUpload() {
    const testUploadArea = document.getElementById('dynamic-test-upload-area');
    const testFileInput = document.getElementById('dynamic-test-file-input');
    
    if (!testUploadArea || !testFileInput) {
        console.log('Dynamic test upload elements not found - skipping test setup');
        return;
    }
    
    setupFileInput(testUploadArea, testFileInput, handleDynamicAnalysisTestFile);
    setupDragAndDrop(testUploadArea, handleDynamicAnalysisTestFile);
    console.log('✅ Dynamic test upload setup complete');
}

/**
 * Handle dynamic test file upload
 * Ori: Dynamic test file handling in original script.js
 */
function handleDynamicAnalysisTestFile(files) {
    if (!files || files.length === 0) return;
    
    const file = files[0]; // Only take the first file for single file test
    
    const validation = validateFile(file);
    if (!validation.success) {
        showNotification(validation.message, 'error');
        return;
    }
    
    dynamicTestFile = file;
    
    // Clear the file input
    const testFileInput = document.getElementById('dynamic-test-file-input');
    if (testFileInput) {
        testFileInput.value = '';
    }
    
    performDynamicAnalysisTest();
}

/**
 * Perform dynamic analysis test
 * Ori: Dynamic test execution in original script.js
 */
async function performDynamicAnalysisTest() {
    if (!dynamicTestFile) return;
    
    const testResults = document.getElementById('dynamic-test-results');
    const testContent = document.getElementById('dynamic-test-content');
    
    if (!testResults || !testContent) {
        console.log('Dynamic test elements not found - performing batch analysis instead');
        dynamicFilesToScan.push(dynamicTestFile);
        updateDynamicAnalysisFileList();
        showNotification(`${dynamicTestFile.name} added to dynamic analysis queue`, 'success');
        return;
    }
    
    // Show loading
    testContent.innerHTML = `
        <div style="text-align: center; padding: 2rem;">
            <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
            <p>Analyzing ${dynamicTestFile.name} with Cuckoo Sandbox...</p>
            <small style="color: #666;">This may take 3-5 minutes for behavioral analysis</small>
        </div>
    `;
    testResults.style.display = 'block';
    
    try {
        const result = await performDynamicFileAnalysis(dynamicTestFile);
        
        if (result.success) {
            displayDynamicAnalysisTestResult(result.data);
        } else {
            testContent.innerHTML = `
                <div style="background: #f8d7da; padding: 1rem; border-radius: 8px; color: #721c24;">
                    <strong><i class="fas fa-exclamation-triangle"></i> Analysis Failed</strong><br>
                    ${result.error || 'Unknown error occurred'}
                </div>
            `;
        }
    } catch (error) {
        testContent.innerHTML = `
            <div style="background: #f8d7da; padding: 1rem; border-radius: 8px; color: #721c24;">
                <strong><i class="fas fa-times-circle"></i> Error</strong><br>
                ${error.message}
            </div>
        `;
    }
}

/**
 * Display dynamic test result
 * Ori: displayDynamicTestResult() in original script.js
 */
function displayDynamicAnalysisTestResult(result) {
    const testResults = document.getElementById('dynamic-test-results');
    const testContent = document.getElementById('dynamic-test-content');
    
    if (!testResults || !testContent) {
        console.error('Dynamic test DOM elements not found');
        return;
    }
    
    testResults.style.display = 'block';
    
    let predictionValue = determineActualPrediction(result);
    const confidence = (result.confidence * 100).toFixed(1);
    const analysisType = result.analysis_type || 'single_model';
    
    testContent.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <h3>${dynamicTestFile.name}</h3>
                <div class="result-badge ${predictionValue === 0 ? 'result-safe' : 'result-threat'}">
                    <i class="fas ${predictionValue === 0 ? 'fa-shield-alt' : 'fa-exclamation-triangle'}"></i>
                    ${result.prediction === 1 ? 'Ransomware' : 'Benign'}
                </div>
            </div>
            
            <div class="analysis-section">
                <h4>
                    <i class="fas ${analysisType === 'ensemble' ? 'fa-brain' : 'fa-play-circle'}"></i> 
                    Dynamic Analysis ${analysisType === 'ensemble' ? '(Ensemble ML)' : '(Behavioral)'}
                    <span class="stage-status stage-completed">
                        <i class="fas fa-check"></i>
                        Completed
                    </span>
                </h4>
                <div class="analysis-details">
                    <div class="detail-item">
                        <span class="detail-label">Prediction:</span>
                        <span class="detail-value">
                            <i class="fas ${predictionValue === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt'}"></i>
                            ${result.prediction === 1 ? 'Ransomware' : 'Benign'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Confidence:</span>
                        <span class="detail-value">${confidence}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Benign Probability:</span>
                        <span class="detail-value">${(result.probabilities.benign * 100).toFixed(1)}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Ransomware Probability:</span>
                        <span class="detail-value">${(result.probabilities.ransomware * 100).toFixed(1)}%</span>
                    </div>
                </div>
                <div class="confidence-bar">
                    <div class="confidence-level" style="width: ${confidence}%; background: ${predictionValue === 1 ? '#f44336' : '#4caf50'};"></div>
                </div>

                ${generateDynamicEnsembleDetailsSection(result.ensemble_details)}
                ${generateDynamicXAIExplanationSection(result.explanation, result.ensemble_details)}
            </div>
        </div>
    `;
}

// ========================================
// INITIALIZATION AND EVENT HANDLING
// ========================================

/**
 * Initialize dynamic page when DOM is loaded
 * Ori: DOMContentLoaded event listener in original script.js
 */
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the dynamic page by looking for dynamic-specific elements
    if (document.getElementById('dynamic-section') || document.getElementById('dynamic-upload-area')) {
        initDynamicAnalysisPage();
        setupDynamicAnalysisTestUpload();
    }
});

/**
 * Initialize dynamic page when navigating to dynamic section
 * Ori: Navigation event handling in original script.js
 */
// document.addEventListener('DOMContentLoaded', () => {
//     const dynamicNavLink = document.querySelector('[data-section="dynamic"]');
//     if (dynamicNavLink) {
//         dynamicNavLink.addEventListener('click', () => {
//             console.log('🔄 Dynamic nav clicked, re-initializing...');
//             setTimeout(() => {
//                 initDynamicAnalysisPage();
//                 setupDynamicAnalysisTestUpload();
//             }, 100);
//         });
//     }
// });


// ========================================
// GLOBAL WINDOW FUNCTIONS (Important for HTML onclick handlers)
// ========================================

// Make functions available globally for onclick handlers
// Ori: Global function exposure in original script.js
window.toggleDynamicAnalysisFeatures = toggleDynamicAnalysisFeatures;
window.toggleDynamicAnalysisIndividualModels = toggleDynamicAnalysisIndividualModels;

// Backwards compatibility with original function names
window.toggleDynamicFeatures = toggleDynamicAnalysisFeatures;
window.toggleIndividualModels = toggleDynamicAnalysisIndividualModels;

// ========================================
// EXPORTS
// ========================================

export {
    // Main initialization functions
    initDynamicAnalysisPage,
    setupDynamicFileUpload,
    setupDynamicEventListeners,
    checkDynamicAnalysisSystemStatus,
    
    // File handling functions
    handleDynamicFileSelection,
    updateDynamicAnalysisFileList,
    clearDynamicAnalysisFiles,
    
    // Scanning functions
    scanDynamicAnalysisFiles,
    performDynamicFileAnalysis,
    
    // UI functions
    showDynamicAnalysisLoading,
    updateDynamicAnalysisProgress,
    updateDynamicAnalysisStats,
    
    // Result display functions
    displayDynamicAnalysisResult,
    displayDynamicAnalysisError,
    generateDynamicEnsembleDetailsSection,
    generateDynamicXAIExplanationSection,
    
    // Helper functions
    toggleDynamicAnalysisFeatures,
    toggleDynamicAnalysisIndividualModels,
    
    // Test functions
    setupDynamicAnalysisTestUpload,
    performDynamicAnalysisTest,
    displayDynamicAnalysisTestResult,
    
    // Variables (for external access if needed)
    dynamicFilesToScan,
    dynamicScanResults,
    dynamicTestFile
};

console.log('✅ dynamic.js (FIXED) loaded - Dynamic Analysis Module Ready');