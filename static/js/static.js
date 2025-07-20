// ========================================
// STATIC.JS - Static Analysis Module
// ========================================
// This file contains all static analysis functionality for the static analysis page

import { 
    API_ENDPOINTS, 
    showNotification, 
    validateFile, 
    formatFileSize,
    setupDragAndDrop,
    setupFileInput,
    makeApiRequest,
    safeGetIndividualModels,
    toggleCollapsibleSection,
    getModelIcon
} from './core.js';

// ========================================
// STATIC-SPECIFIC VARIABLES
// ========================================

let staticAnalysisFile = null;
let staticFilesToScan = [];
let staticScanResults = [];

// ========================================
// DOM ELEMENTS
// ========================================

const staticUploadArea = document.getElementById('static-upload-area');
const staticFileInput = document.getElementById('static-file-input');
const staticResults = document.getElementById('static-results');
const staticContent = document.getElementById('static-content');
const staticResultsContainer = document.getElementById('static-results-container');
const staticFileListContainer = document.getElementById('static-file-list-container');
const staticFileList = document.getElementById('static-file-list');
const staticScanButton = document.getElementById('static-scan-button');
const staticClearButton = document.getElementById('static-clear-button');
const staticLoading = document.getElementById('static-loading');
const staticLoadingText = document.getElementById('static-loading-text');
const staticProgressBar = document.getElementById('static-progress-fill');
const staticCurrentFile = document.getElementById('static-current-file');
const staticResultsArea = document.getElementById('static-results-area');
const staticTotalAnalyzed = document.getElementById('static-total-analyzed');
const staticSafeCount = document.getElementById('static-safe-count');
const staticThreatCount = document.getElementById('static-threat-count');
const staticEnsembleCount = document.getElementById('static-ensemble-count');

// ========================================
// CORE STATIC FUNCTIONS
// ========================================

/**
 * Initialize static analysis page
 */
function initializeStaticPage() {
    console.log('🔥 Initializing Static Analysis Page...');
    
    // Debug: Check if we're on the right page
    console.log('Static elements check:');
    console.log('- Upload area:', document.getElementById('static-upload-area'));
    console.log('- File input:', document.getElementById('static-file-input'));
    console.log('- Results container:', document.getElementById('static-results-container'));
    
    // Load model information
    loadStaticModelInfo();
    
    // Setup upload functionality
    setupStaticUpload();
    
    console.log('✅ Static Analysis Page initialized');
}

/**
 * Load static model information
 */
async function loadStaticModelInfo() {
    try {
        const response = await makeApiRequest(API_ENDPOINTS.MODEL_INFO);
        
        if (response.success && response.data.status === 'success') {
            const staticModel = response.data.static_model;
            
            // Update status cards if they exist
            updateStaticStatusCards(staticModel);
            
            // Display detailed model information
            displayStaticModelDetails(staticModel);
        } else {
            console.error('Failed to load static model info:', response.error);
        }
    } catch (error) {
        console.error('Error loading static model info:', error);
    }
}

/**
 * Update static status cards
 * @param {Object} staticModel - Static model information
 */
function updateStaticStatusCards(staticModel) {
    const elements = {
        'static-model-count': staticModel.model_count || 0,
        'static-feature-count': staticModel.feature_count || 0,
        'static-voting-strategy': (staticModel.voting_strategy || 'majority_vote').replace(/_/g, ' '),
        'static-status': staticModel.loaded ? 'Ready' : 'Not Ready'
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });
    
    // Update status colors
    const statusElement = document.getElementById('static-status');
    if (statusElement && staticModel.loaded) {
        const parentElement = statusElement.parentElement;
        if (parentElement) {
            parentElement.style.background = 'linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%)';
            const iconElement = parentElement.querySelector('.stat-icon');
            if (iconElement) {
                iconElement.style.color = '#28a745';
            }
        }
    }
}

/**
 * Display detailed static model information
 * @param {Object} staticModel - Static model information
 */
function displayStaticModelDetails(staticModel) {
    const detailsContainer = document.getElementById('static-model-details');
    if (!detailsContainer) return;
    
    if (!staticModel.loaded) {
        detailsContainer.innerHTML = `
            <div style="background: #f8d7da; padding: 1rem; border-radius: 8px; color: #721c24; margin-top: 1rem;">
                <strong><i class="fas fa-exclamation-triangle"></i> Models Not Loaded</strong><br>
                Static ensemble models are not available.
            </div>
        `;
        return;
    }
    
    let modelsHtml = '';
    if (staticModel.individual_models) {
        modelsHtml = `
            <div style="margin-top: 1.5rem;">
                <h3><i class="fas fa-layer-group"></i> Individual Models</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-top: 1rem;">
        `;
        
        Object.entries(staticModel.individual_models).forEach(([modelName, modelType]) => {
            const displayName = modelName.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
            const icon = getModelIcon(modelName);
            
            modelsHtml += `
                <div style="padding: 1rem; background: white; border-radius: 8px; border-left: 4px solid #28a745;">
                    <h4 style="margin: 0 0 0.5rem 0; color: #28a745;">
                        <i class="fas fa-${icon}"></i> ${displayName}
                    </h4>
                    <p style="margin: 0; color: #666; font-size: 0.9rem;">Type: ${modelType || 'Unknown'}</p>
                    <p style="margin: 0.5rem 0 0 0; color: #28a745; font-weight: 600; font-size: 0.9rem;">
                        <i class="fas fa-check-circle"></i> Loaded & Ready
                    </p>
                </div>
            `;
        });
        
        modelsHtml += `</div></div>`;
    }
    
    detailsContainer.innerHTML = modelsHtml;
}

// ========================================
// STATIC UPLOAD FUNCTIONS
// ========================================

/**
 * Setup static upload functionality
 */
function setupStaticUpload() {
    console.log('🔧 Setting up static upload...');
    
    if (!staticUploadArea || !staticFileInput) {
        console.error('Static upload elements not found');
        return;
    }
    
    setupFileInput(staticUploadArea, staticFileInput, handleStaticFile);
    setupDragAndDrop(staticUploadArea, handleStaticFile);
    
    // Setup button event listeners
    if (staticScanButton) {
        staticScanButton.addEventListener('click', scanStaticFiles);
    }
    
    if (staticClearButton) {
        staticClearButton.addEventListener('click', clearStaticFiles);
    }
    
    console.log('✅ Static upload setup complete');
}

/**
 * Handle static file upload
 * @param {FileList} files - Selected files
 */
function handleStaticFile(files) {
    console.log('🔍 DEBUG: handleStaticFile called with files:', files);

    if (!files || files.length === 0) return;
    
    const validFiles = [];
    
    for (let file of files) {
        const validation = validateFile(file);
        
        if (!validation.success) {
            showNotification(validation.message, 'error');
            continue;
        }
        
        // Check if file already exists
        const isDuplicate = staticFilesToScan.some(f => 
            f.name === file.name && f.size === file.size
        );
        
        if (!isDuplicate) {
            validFiles.push(file);
        }
    }
    
    // Add valid files to the list
    staticFilesToScan.push(...validFiles);
    
    // Update the file list display
    updateStaticFileList();
    
    // Show success notification if files were added
    if (validFiles.length > 0) {
        showNotification(`${validFiles.length} file(s) added for static analysis`, 'success');
    }
}

function updateStaticFileList() {
    if (!staticFileListContainer || !staticFileList) return;
    
    if (staticFilesToScan.length > 0) {
        staticFileListContainer.style.display = 'block';
        staticFileList.innerHTML = '';
        
        staticFilesToScan.forEach((file, index) => {
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
            removeButton.addEventListener('click', () => removeStaticFile(index));
            
            li.appendChild(nameSpan);
            li.appendChild(removeButton);
            staticFileList.appendChild(li);
        });
    } else {
        staticFileListContainer.style.display = 'none';
    }
}

function removeStaticFile(index) {
    if (index >= 0 && index < staticFilesToScan.length) {
        const removedFile = staticFilesToScan.splice(index, 1)[0];
        updateStaticFileList();
        showNotification(`${removedFile.name} removed from static analysis`, 'info');
    }
}

function clearStaticFiles() {
    staticFilesToScan = [];
    updateStaticFileList();
    hideStaticResults();
    showNotification('All files cleared from static analysis', 'info');
}

function scanStaticFiles() {
    console.log('🔍 DEBUG: scanStaticFiles called');

    if (staticFilesToScan.length === 0) {
        showNotification('No files selected for static analysis', 'error');
        return;
    }
    
    // Start the batch analysis
    performBatchStaticAnalysis();
}

async function performBatchStaticAnalysis() {
    console.log('🔍 DEBUG: performBatchStaticAnalysis called');
    // Show loading and disable buttons
    showStaticLoading(true);
    
    // Clear previous results
    staticScanResults = [];
    clearStaticResultsArea();
    
    let safeCnt = 0;
    let threatCnt = 0;
    
    for (let i = 0; i < staticFilesToScan.length; i++) {
        const file = staticFilesToScan[i];
        
        try {
            // Update progress
            updateStaticProgress(i + 1, staticFilesToScan.length, file.name);
            
            // Perform static analysis
            const result = await performSingleStaticAnalysis(file);
            
            if (result.success) {
                staticScanResults.push(result.data);
                displaySingleStaticResult(file.name, result.data);
                
                // Update counters - FIXED
                const prediction = result.data.result?.prediction ?? 
                                  result.data.prediction ?? 
                                  (result.data.prediction_label === 'Ransomware' ? 1 : 0);

                if (prediction === 1) {
                    threatCnt++;
                } else {
                    safeCnt++;
                }
            } else {
                displayStaticError(file.name, result.error);
            }
            
        } catch (error) {
            console.error(`Static analysis error for ${file.name}:`, error);
            displayStaticError(file.name, error.message);
        }
    }
    
    // Update final statistics
    updateStaticStats(safeCnt, threatCnt);
    
    // Show results and hide loading
    showStaticResultsContainer();
    showStaticLoading(false);
    
    // Show completion notification
    const totalFiles = safeCnt + threatCnt;
    showNotification(`Static analysis complete! ${totalFiles} files processed, ${threatCnt} threats detected.`, 'success');
}

async function performSingleStaticAnalysis(file) {
    console.log('🔍 DEBUG: performSingleStaticAnalysis called with file:', file.name);
    const formData = new FormData();
    formData.append('file', file);
    
    return await makeApiRequest(API_ENDPOINTS.STATIC_ANALYSIS, {
        method: 'POST',
        body: formData
    });
}

function displaySingleStaticResult(fileName, data) {
    console.log('🔍 DEBUG: displaySingleStaticResult called with:', fileName, data);


    if (!staticResultsArea) return;
    
    const result = data.result || data.static_analysis || data;
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    const prediction = result.prediction !== undefined ? result.prediction : 
                      result.prediction_label === 'Ransomware' ? 1 : 0;
    
    const predictionLabel = prediction === 1 ? 'Ransomware' : 'Benign';
    const predictionClass = prediction === 1 ? 'result-threat' : 'result-safe';
    const predictionIcon = prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt';
    const confidence = result.confidence ? (result.confidence * 100).toFixed(1) : 'N/A';
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3><i class="fas fa-file"></i> ${fileName}</h3>
            <div class="result-badge ${predictionClass}">
                <i class="fas ${predictionIcon}"></i>
                ${predictionLabel.toUpperCase()} (${confidence}%)
            </div>
        </div>
        <div class="result-body">
            <div class="analysis-section">
                <h4>
                    <i class="fas fa-file-code"></i> Static Analysis (PE Features)
                    <span class="stage-status stage-completed">
                        <i class="fas fa-check"></i>
                        Completed
                    </span>
                </h4>
                <div class="analysis-details">
                    <div class="detail-item">
                        <span class="detail-label">Prediction:</span>
                        <span class="detail-value">
                            <i class="fas ${predictionIcon}"></i>
                            ${predictionLabel}
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Confidence:</span>
                        <span class="detail-value">${confidence}%</span>
                    </div>
                    ${result.probabilities ? `
                    <div class="detail-item">
                        <span class="detail-label">Benign Probability:</span>
                        <span class="detail-value">${(result.probabilities.benign * 100).toFixed(1)}%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Ransomware Probability:</span>
                        <span class="detail-value">${(result.probabilities.ransomware * 100).toFixed(1)}%</span>
                    </div>
                    ` : ''}
                </div>
                <div class="confidence-bar">
                    <div class="confidence-level" style="width: ${confidence}%; background: ${prediction === 1 ? '#f44336' : '#4caf50'};"></div>
                </div>
                ${generateStaticEnsembleDetailsSection(result.ensemble_details)}
                ${generateStaticXAIExplanationSection(result.explanation)}
            </div>
        </div>
    `;
    
    staticResultsArea.appendChild(resultCard);

    // Add this debug line to see what HTML is being generated
    console.log('🔍 DEBUG: Generated HTML preview:', resultCard.innerHTML.substring(0, 500));
    console.log('🔍 DEBUG: ResultCard className:', resultCard.className);
    
    console.log('🔍 DEBUG: staticResultsArea after append:', staticResultsArea);
    console.log('🔍 DEBUG: staticResultsArea innerHTML length:', staticResultsArea.innerHTML.length);
    console.log('🔍 DEBUG: staticResultsArea children count:', staticResultsArea.children.length);
}

function displayStaticError(fileName, errorMessage) {
    if (!staticResultsArea) return;
    
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card result-error';
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3><i class="fas fa-file"></i> ${fileName}</h3>
            <div class="result-badge" style="background-color: #f44336;">
                <i class="fas fa-times-circle"></i>
                ERROR
            </div>
        </div>
    `;
    
    staticResultsArea.appendChild(resultCard);
}

function showStaticLoading(show) {
    if (staticLoading) {
        staticLoading.style.display = show ? 'flex' : 'none';
    }
    
    if (staticScanButton) {
        staticScanButton.disabled = show;
    }
    
    if (staticClearButton) {
        staticClearButton.disabled = show;
    }
}

function updateStaticProgress(current, total, fileName) {
    const progress = (current / total) * 100;
    
    if (staticProgressBar) {
        staticProgressBar.style.width = `${progress}%`;
    }
    
    if (staticCurrentFile) {
        staticCurrentFile.innerHTML = `<i class="fas fa-file"></i> Analyzing: ${fileName}`;
    }
    
    if (staticLoadingText) {
        staticLoadingText.innerHTML = `Analyzing files... (${current}/${total})<br><br>`;
    }
}

function updateStaticStats(safeCount, threatCount) {
    console.log('🔍 DEBUG: updateStaticStats called with:', safeCount, threatCount);
    const totalCount = safeCount + threatCount;
    
    if (staticTotalAnalyzed) {
        staticTotalAnalyzed.textContent = totalCount;
    }
    if (staticSafeCount) {
        staticSafeCount.textContent = safeCount;
    }
    if (staticThreatCount) {
        staticThreatCount.textContent = threatCount;
    }
    if (staticEnsembleCount) {
        staticEnsembleCount.textContent = totalCount; // All static analyses use ensemble
    }
}

function showStaticResultsContainer() {
    console.log('🔍 DEBUG: showStaticResultsContainer called');
    console.log('🔍 DEBUG: staticResultsContainer element:', staticResultsContainer);
    if (staticResultsContainer) {
        staticResultsContainer.style.display = 'block';
    }
}

function clearStaticResultsArea() {
    if (staticResultsArea) {
        staticResultsArea.innerHTML = '';
    }
}

/**
 * Perform static analysis
 */
async function performStaticAnalysis() {
    console.log('🔍 DEBUG: performStaticAnalysis called with file:', staticAnalysisFile);

    if (!staticAnalysisFile) return;
    
    if (!staticResults || !staticContent) {
        console.error('Static DOM elements not found');
        return;
    }
    
    // Show loading in results section
    staticContent.innerHTML = `
        <div style="text-align: center; padding: 2rem;">
            <div class="spinner"><i class="fas fa-cog fa-spin"></i></div>
            <p>Analyzing ${staticAnalysisFile.name}...</p>
        </div>
    `;
    
    // Show both results elements
    staticResults.style.display = 'block';
    
    // Show the results container
    if (staticResultsContainer) {
        staticResultsContainer.style.display = 'block';

        console.log('🔍 DEBUG: staticResultsContainer display set to block');
        console.log('🔍 DEBUG: staticResultsContainer computed style:', window.getComputedStyle(staticResultsContainer));
        
        // Scroll to results section smoothly
        staticResultsContainer.scrollIntoView({ 
            behavior: 'smooth',
            block: 'start'
        });
    }
    
    try {
        const formData = new FormData();
        formData.append('file', staticAnalysisFile);
        
        const response = await makeApiRequest(API_ENDPOINTS.STATIC_ANALYSIS, {
            method: 'POST',
            body: formData
        });
        
        if (response.success && response.data.status === 'success') {
            // lts(response.data);
            displayStaticResults(response.data);
        } else {
            throw new Error(response.error || 'Static analysis failed');
        }
        
    } catch (error) {
        console.error('Error performing static analysis:', error);
        staticContent.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: #f44336;">
                <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Error analyzing file: ${error.message}</p>
                <button onclick="hideStaticResults()" style="margin-top: 1rem; padding: 0.5rem 1rem; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer;">
                    <i class="fas fa-times"></i> Close
                </button>
            </div>
        `;
        showNotification(`Error analyzing file: ${error.message}`, 'error');
    }
}

/**
 * Reset static analysis - clear file and hide results
 */
function resetStaticAnalysis() {
    // Clear the file
    staticAnalysisFile = null;
    
    // Clear file input
    if (staticFileInput) {
        staticFileInput.value = '';
    }
    
    // Hide results
    hideStaticResults();
    
    // Clear results content
    if (staticContent) {
        staticContent.innerHTML = '';
    }
    
    // Show success message
    showNotification('Static analysis reset successfully', 'success');
}

/**
 * Display static analysis results
 * @param {Object} data - API response data
 */
function displayStaticResults(data) {
    console.log('🔍 DEBUG: displayStaticResults called');
    console.log('🔍 DEBUG: staticContent element:', staticContent);
    console.log('🔍 DEBUG: staticResultsContainer element:', staticResultsContainer);
    console.log('🔍 DEBUG: API response data:', data);

    if (!staticContent) return;
    
    console.log('API Response Data:', data); // Debug log
    
    // Handle different possible response structures
    const result = data.result || data.static_analysis || data;
    
    if (!result) {
        console.error('No result data found in API response');
        staticContent.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: #f44336;">
                <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Invalid API response structure</p>
                <pre style="text-align: left; background: #f5f5f5; padding: 1rem; border-radius: 4px; overflow-x: auto;">${JSON.stringify(data, null, 2)}</pre>
            </div>
        `;
        return;
    }
    
    const filename = staticAnalysisFile ? staticAnalysisFile.name : 'Unknown';
    
    // Handle prediction field
    const prediction = result.prediction !== undefined ? result.prediction : 
                      result.prediction_label === 'Ransomware' ? 1 : 0;
    
    const predictionLabel = prediction === 1 ? 'Ransomware' : 'Benign';
    const predictionClass = prediction === 1 ? 'result-threat' : 'result-safe';
    const predictionIcon = prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt';
    const confidence = result.confidence ? (result.confidence * 100).toFixed(1) : 'N/A';
    
    staticContent.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <div class="file-info">
                    <h3>${filename}</h3>
                </div>
                <div class="result-badge ${predictionClass}">
                    <i class="fas ${predictionIcon}"></i>
                    ${predictionLabel} (${confidence}%)
                </div>
            </div>
            <div class="result-body">
                ${generateStaticAnalysisSection(result)}
            </div>
        </div>
    `;

    console.log('🔍 DEBUG: Results HTML set, container should be visible');
    console.log('🔍 DEBUG: staticResultsContainer display:', staticResultsContainer.style.display);
    console.log('🔍 DEBUG: staticResultsContainer offsetHeight:', staticResultsContainer.offsetHeight);
}

// ========================================
// STATIC RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Generate static analysis section
 * @param {Object} staticAnalysis - Static analysis data
 * @returns {string} HTML string for static analysis section
 */
function generateStaticAnalysisSection(staticAnalysis) {
    if (!staticAnalysis) return '';
    
    // Handle when static analysis was skipped
    if (!staticAnalysis.performed || staticAnalysis.status === 'skipped') {
        return `
            <div class="analysis-section">
                <h4>
                    <i class="fas fa-file-code"></i> Static Analysis
                    <span class="stage-status stage-skipped">
                        <i class="fas fa-minus-circle"></i>
                        Skipped
                    </span>
                </h4>
                <p style="color: #666; font-style: italic;">
                    <i class="fas fa-info-circle"></i>
                    ${staticAnalysis.reason || 'Static analysis was not performed.'}
                </p>
            </div>
        `;
    }
    
    const confidence = (staticAnalysis.confidence * 100).toFixed(1);
    const statusClass = 'stage-completed';
    const statusText = 'Completed';
    
    return `
        <div class="analysis-section">
            <h4>
                <i class="fas fa-file-code"></i> Static Analysis (PE Features)
                <span class="stage-status ${statusClass}">
                    <i class="fas fa-check"></i>
                    ${statusText}
                </span>
            </h4>
            <div class="analysis-details">
                <div class="detail-item">
                    <span class="detail-label">Prediction:</span>
                    <span class="detail-value">
                        <i class="fas ${staticAnalysis.prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt'}"></i>
                        ${staticAnalysis.prediction_label}
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${confidence}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Benign Probability:</span>
                    <span class="detail-value">${(staticAnalysis.probabilities.benign * 100).toFixed(1)}%</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Ransomware Probability:</span>
                    <span class="detail-value">${(staticAnalysis.probabilities.ransomware * 100).toFixed(1)}%</span>
                </div>
            </div>
            <div class="confidence-bar">
                <div class="confidence-level" style="width: ${confidence}%; background: ${staticAnalysis.prediction === 1 ? '#f44336' : '#4caf50'};"></div>
            </div>
            ${generateStaticEnsembleDetailsSection(staticAnalysis.ensemble_details)}
            ${generateStaticXAIExplanationSection(staticAnalysis.explanation)}
            ${staticAnalysis.execution_time ? `<small style="color: #666; margin-top: 0.5rem; display: block;"><i class="fas fa-clock"></i> Execution time: ${(staticAnalysis.execution_time * 1000).toFixed(0)}ms</small>` : ''}
        </div>
    `;
}

/**
 * Generate static ensemble voting details section
 * @param {Object} ensembleDetails - Ensemble details
 * @returns {string} HTML string for ensemble details
 */
function generateStaticEnsembleDetailsSection(ensembleDetails) {
    if (!ensembleDetails || !ensembleDetails.individual_models) return '';
    
    const individualModels = ensembleDetails.individual_models;
    
    // Calculate votes first
    let ransomwareVotes = 0;
    let benignVotes = 0;
    
    Object.values(individualModels).forEach(result => {
        if (result.prediction === 1) {
            ransomwareVotes++;
        } else {
            benignVotes++;
        }
    });
    
    let content = `
        <div class="ensemble-section">
            <h5><i class="fas fa-vote-yea"></i> Static Ensemble Voting Results</h5>
            <div class="voting-summary">
    `;
    
    // Display individual model votes
    Object.entries(individualModels).forEach(([modelName, result]) => {
        const nameMapping = {
            'randomforest': 'Random Forest',
            'xgboost': 'XGBoost',
            'svm': 'SVM'
        };
        const modelDisplayName = nameMapping[modelName] || modelName;
        const voteClass = result.prediction === 1 ? 'vote-threat' : 'vote-safe';
        const voteIcon = result.prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt';
        
        content += `
            <div class="model-vote">
                <div class="model-name">${modelDisplayName}</div>
                <div class="vote-result ${voteClass}">
                    <i class="fas ${voteIcon}"></i>
                    ${result.prediction_label}
                </div>
                <div class="vote-confidence">${(result.confidence * 100).toFixed(1)}%</div>
            </div>
        `;
    });
    
    content += `</div>`;
    
    // Add voting summary
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
 * Generate static XAI explanation section
 * @param {Object} explanation - XAI explanation data
 * @returns {string} HTML string for XAI explanation
 */
function generateStaticXAIExplanationSection(explanation) {
    // Safety check for explanation object
    if (!explanation || typeof explanation !== 'object') {
        return `
            <div class="xai-section">
                <h5><i class="fas fa-brain"></i> Static XAI Feature Explanation</h5>
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; color: #856404;">
                    <i class="fas fa-info-circle"></i> XAI explanation data not available for this analysis.
                </div>
            </div>
        `;
    }

    // Check if explanation data exists and has the expected structure
    if (!explanation || (!explanation.feature_contributions && !safeGetIndividualModels(explanation))) {
        return `
            <div class="xai-section">
                <h5><i class="fas fa-brain"></i> Static XAI Feature Explanation</h5>
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; color: #856404;">
                    <i class="fas fa-info-circle"></i> XAI explanation data not available for this analysis.
                </div>
            </div>
        `;
    }
    
    const topFeatures = explanation.feature_contributions?.top_features || [];
    const explanationText = explanation.feature_contributions?.prediction_explanation || 'Static feature analysis completed.';
    
    let content = `
        <div class="xai-section">
            <h5><i class="fas fa-brain"></i> Static XAI Feature Explanation</h5>
            <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 4px solid #ff9800;">
                <strong><i class="fas fa-lightbulb"></i> Static Feature Analysis:</strong><br>
                <em>${explanationText}</em>
            </div>
    `;
    
    if (topFeatures.length > 0) {
        content += `
            <div>
                <strong><i class="fas fa-list-ol"></i> Top Contributing Static Features:</strong>
                <div style="margin-top: 0.5rem;">
        `;
        
        // Show first 5 features
        const initialFeatures = topFeatures.slice(0, 5);
        const remainingFeatures = topFeatures.slice(5);
        
        // Generate unique ID for this section
        const uniqueId = 'static-features-' + Math.random().toString(36).substr(2, 9);
        
        // Display initial 5 features
        initialFeatures.forEach((feature) => {
            const impactClass = feature.shap_value > 0 ? 'impact-positive' : 'impact-negative';
            const impactIcon = feature.shap_value > 0 ? 'fa-arrow-up' : 'fa-arrow-down';
            const impactText = feature.contribution_type || (feature.shap_value > 0 ? 'Increases Ransomware Risk' : 'Decreases Ransomware Risk');
            
            content += `
                <div class="feature-contribution">
                    <span class="feature-name">${feature.feature_name || `Feature ${feature.feature_id}`}</span>
                    <span class="feature-impact ${impactClass}">
                        <i class="fas ${impactIcon}"></i>
                        ${Math.abs(feature.shap_value || 0).toFixed(3)} (${impactText})
                    </span>
                </div>
            `;
        });
        
        // Add remaining features (hidden initially)
        if (remainingFeatures.length > 0) {
            content += `
                <div id="${uniqueId}-hidden" style="display: none;">
            `;
            
            remainingFeatures.forEach((feature) => {
                const impactClass = feature.shap_value > 0 ? 'impact-positive' : 'impact-negative';
                const impactIcon = feature.shap_value > 0 ? 'fa-arrow-up' : 'fa-arrow-down';
                const impactText = feature.contribution_type || (feature.shap_value > 0 ? 'Increases Ransomware Risk' : 'Decreases Ransomware Risk');
                
                content += `
                    <div class="feature-contribution">
                        <span class="feature-name">${feature.feature_name || `Feature ${feature.feature_id}`}</span>
                        <span class="feature-impact ${impactClass}">
                            <i class="fas ${impactIcon}"></i>
                            ${Math.abs(feature.shap_value || 0).toFixed(3)} (${impactText})
                        </span>
                    </div>
                `;
            });
            
            content += `</div>`;
            
            // Add show/hide button
            content += `
                <div style="text-align: right; margin-top: 0.5rem;">
                    <span id="${uniqueId}-toggle" onclick="toggleStaticFeatures('${uniqueId}')" 
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
    
    // Add ensemble SHAP info if available
    if (explanation.ensemble_shap_available) {
        content += `
            <div style="margin-top: 1rem; padding: 0.5rem; background: rgba(76, 175, 80, 0.1); border-radius: 4px; color: #2e7d32;">
                <i class="fas fa-check-circle"></i> Ensemble SHAP explanations computed across all static models
            </div>
        `;
    }

    // Add individual model explanations if available
    if (explanation && safeGetIndividualModels(explanation) && Object.keys(safeGetIndividualModels(explanation)).length > 0) {
        const individualModels = safeGetIndividualModels(explanation);
        const individualModelsCount = Object.keys(individualModels).length;
        
        content += `
            <div style="margin-top: 1.5rem; padding: 1rem; background: #f2f2f2; border-radius: 8px;">
                <div class="individual-models-header" style="cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: white; border-radius: 6px; border: 1px solid #e0e0e0;" onclick="toggleIndividualModels(this)">
                    <strong><i class="fas fa-microscope"></i> Individual Static Model Explanations (${individualModelsCount} models)</strong>
                    <i class="fas fa-chevron-down toggle-icon" style="transition: transform 0.3s ease;"></i>
                </div>
                <div class="individual-models-content" style="display: none; margin-top: 1rem;">
        `;
        
        Object.entries(individualModels).forEach(([modelName, modelData]) => {
            if (!modelData.error && modelData.top_features) {
                const nameMapping = {
                    'randomforest': 'Random Forest',
                    'xgboost': 'XGBoost',
                    'svm': 'SVM'
                };
                const modelDisplayName = nameMapping[modelName] || modelName;
                const confidencePercent = (modelData.confidence * 100).toFixed(1);
                const borderColor = modelData.prediction === 1 ? '#e74c3c' : '#27ae60';
                const textColor = modelData.prediction === 1 ? '#e74c3c' : '#27ae60';
                const predictionIcon = modelData.prediction === 1 ? 'fa-exclamation-triangle' : 'fa-shield-alt';
                
                content += `
                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 4px solid ${borderColor}; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                            <h6 style="margin: 0; font-size: 1rem; font-weight: 600;">
                                <i class="fas fa-brain" style="margin-right: 8px; color: ${borderColor};"></i>
                                ${modelDisplayName}
                            </h6>
                            <div style="text-align: right;">
                                <span style="color: ${textColor}; font-weight: bold; font-size: 0.9rem;">
                                    <i class="fas ${predictionIcon}"></i> ${modelData.prediction_label}
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
                
                modelData.top_features.forEach((feature) => {
                    const impact = feature.shap_value > 0 ? 'Increases Risk' : 'Decreases Risk';
                    const icon = feature.shap_value > 0 ? '📈' : '📉';
                    const impactColor = feature.shap_value > 0 ? '#e74c3c' : '#27ae60';
                    const featureName = feature.feature_name.length > 50 ? 
                        feature.feature_name.substring(0, 50) + '...' : feature.feature_name;
                    
                    content += `
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.6rem; background: #f8f9fa; border-radius: 4px; border-left: 3px solid ${impactColor};">
                            <div style="flex: 1;">
                                <span style="font-weight: 500; font-size: 0.85rem;">${icon} ${featureName}</span>
                                ${feature.feature_name.length > 50 ? `<div style="font-size: 0.7rem; color: #666; margin-top: 2px;" title="${feature.feature_name}">${feature.feature_name}</div>` : ''}
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
// STATIC HELPER FUNCTIONS
// ========================================

/**
 * Toggle static features display
 * @param {string} uniqueId - Unique identifier for the features section
 */
function toggleStaticFeatures(uniqueId) {
    const hiddenSection = document.getElementById(`${uniqueId}-hidden`);
    const toggleButton = document.getElementById(`${uniqueId}-toggle`);
    
    if (hiddenSection && toggleButton) {
        if (hiddenSection.style.display === 'none') {
            // Show more features
            hiddenSection.style.display = 'block';
            toggleButton.textContent = 'Show less...';
        } else {
            // Hide extra features
            hiddenSection.style.display = 'none';
            const remainingCount = hiddenSection.children.length;
            toggleButton.textContent = `Show ${remainingCount} more features...`;
        }
    }
}

/**
 * Toggle individual models dropdown
 * @param {HTMLElement} headerElement - Header element that was clicked
 */
function toggleIndividualModels(headerElement) {
    toggleCollapsibleSection(headerElement);
}

/**
 * Hide static results section
 */
function hideStaticResults() {
    if (staticResultsContainer) {
        staticResultsContainer.style.display = 'none';
    }
    if (staticResults) {
        staticResults.style.display = 'none';
    }
}

// ========================================
// INITIALIZATION AND EVENT HANDLING
// ========================================

/**
 * Initialize static page when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 DOM Content Loaded - Checking for static elements...');
    
    // Check if we're on the static page by looking for static-specific elements
    const staticElements = {
        uploadArea: document.getElementById('static-upload-area'),
        fileInput: document.getElementById('static-file-input'),
        staticSection: document.getElementById('static-section'),
        resultsContainer: document.getElementById('static-results-container')
    };
    
    console.log('Static elements found:', staticElements);
    
    if (staticElements.uploadArea || staticElements.staticSection) {
        console.log('✅ Static page detected, initializing...');
        initializeStaticPage();
    } else {
        console.log('❌ Static page elements not found');
    }
});

// Make functions available globally for onclick handlers
window.toggleStaticFeatures = toggleStaticFeatures;
window.toggleIndividualModels = toggleIndividualModels;
window.hideStaticResults = hideStaticResults;
window.resetStaticAnalysis = resetStaticAnalysis;

// ========================================
// EXPORTS
// ========================================

export {
    initializeStaticPage,
    loadStaticModelInfo,
    performStaticAnalysis,
    displayStaticResults,
    generateStaticAnalysisSection,
    generateStaticEnsembleDetailsSection,
    generateStaticXAIExplanationSection,
    staticAnalysisFile
};

console.log('✅ static.js loaded - Static Analysis Module Ready');