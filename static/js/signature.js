// ========================================
// SIGNATURE.JS - Signature Analysis Module
// ========================================
// This file contains all signature analysis functionality for the signature validation page

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
    makeApiRequest
} from './core.js';

// ========================================
// SIGNATURE-SPECIFIC VARIABLES
// ========================================

let signatureFilesToScan = [];
let signatureScanResults = [];

// ========================================
// DOM ELEMENTS
// ========================================

const signatureUploadArea = document.getElementById('signature-upload-area');
const signatureFileInput = document.getElementById('signature-file-input');
const signatureFileListContainer = document.getElementById('signature-file-list-container');
const signatureFileList = document.getElementById('signature-file-list');
const signatureScanButton = document.getElementById('signature-scan-button');
const signatureClearButton = document.getElementById('signature-clear-button');
const signatureLoading = document.getElementById('signature-loading');
const signatureLoadingText = document.getElementById('signature-loading-text');
const signatureProgressBar = document.getElementById('signature-progress-fill');
const signatureCurrentFile = document.getElementById('signature-current-file');
const signatureResultsContainer = document.getElementById('signature-results-container');
const signatureResultsArea = document.getElementById('signature-results-area');
const signatureTotalScanned = document.getElementById('signature-total-scanned');
const signatureSafeCount = document.getElementById('signature-safe-count');
const signatureThreatCount = document.getElementById('signature-threat-count');
const signatureUnknownCount = document.getElementById('signature-unknown-count');

// ========================================
// CORE SIGNATURE FUNCTIONS
// ========================================

/**
 * Initialize signature analysis page
 */
function initializeSignaturePage() {
    console.log('🔥 Initializing Signature Analysis Page...');
    
    // Setup file upload functionality
    if (signatureUploadArea && signatureFileInput) {
        setupFileInput(signatureUploadArea, signatureFileInput, handleSignatureFiles);
        setupDragAndDrop(signatureUploadArea, handleSignatureFiles);
    }
    
    // Setup button event listeners
    if (signatureScanButton) {
        signatureScanButton.addEventListener('click', scanSignatureFiles);
    }
    
    if (signatureClearButton) {
        signatureClearButton.addEventListener('click', clearSignatureFiles);
    }
    
    console.log('✅ Signature Analysis Page initialized');
}

/**
 * Handle signature file selection (from file input)
 * @param {Event} event - File input change event
 */
function handleSignatureFileSelection(event) {
    handleSignatureFiles(event.target.files);
}

/**
 * Process signature files for upload
 * @param {FileList} fileList - List of files to process
 */
function handleSignatureFiles(fileList) {
    const result = processFiles(fileList, signatureFilesToScan);
    
    // Show errors for invalid files
    result.errors.forEach(error => {
        showNotification(error, 'error');
    });
    
    // Add valid files to the list
    signatureFilesToScan.push(...result.validFiles);
    
    // Update the file list display
    updateSignatureFileList();
    
    // Show success notification if files were added
    if (result.validFiles.length > 0) {
        showNotification(`${result.validFiles.length} file(s) added for signature analysis`, 'success');
    }
}

/**
 * Update the signature file list display
 */
function updateSignatureFileList() {
    displayFileList(signatureFilesToScan, signatureFileListContainer, removeSignatureFile);
}

/**
 * Remove a file from the signature files list
 * @param {number} index - Index of file to remove
 */
function removeSignatureFile(index) {
    if (index >= 0 && index < signatureFilesToScan.length) {
        const removedFile = signatureFilesToScan.splice(index, 1)[0];
        updateSignatureFileList();
        showNotification(`${removedFile.name} removed from signature analysis`, 'info');
    }
}

/**
 * Clear all signature files
 */
function clearSignatureFiles() {
    signatureFilesToScan = [];
    updateSignatureFileList();
    hideSignatureResults();
    showNotification('All files cleared from signature analysis', 'info');
}

/**
 * Hide signature results container
 */
function hideSignatureResults() {
    if (signatureResultsContainer) {
        signatureResultsContainer.style.display = 'none';
    }
    if (signatureResultsArea) {
        signatureResultsArea.innerHTML = '';
    }
}

// ========================================
// SIGNATURE SCANNING FUNCTIONS
// ========================================

/**
 * Scan all signature files
 */
async function scanSignatureFiles() {
    if (signatureFilesToScan.length === 0) {
        showNotification('No files selected for signature analysis', 'error');
        return;
    }
    
    // Show loading and disable buttons
    showSignatureLoading(true);
    
    // Clear previous results
    signatureScanResults = [];
    clearSignatureResultsArea();
    
    let safeCnt = 0;
    let threatCnt = 0;
    let unknownCnt = 0;
    
    console.log(`🔥 Starting signature analysis for ${signatureFilesToScan.length} files...`);
    
    for (let i = 0; i < signatureFilesToScan.length; i++) {
        const file = signatureFilesToScan[i];
        
        try {
            // Update progress
            updateSignatureProgress(i + 1, signatureFilesToScan.length, file.name);
            
            // Perform signature analysis
            const result = await performSignatureAnalysis(file);
            
            if (result.success) {
                signatureScanResults.push(result.data);
                displaySignatureResult(file.name, result.data);
                
                // Update counters
                if (result.data.decision === 'malicious') {
                    threatCnt++;
                } else if (result.data.decision === 'benign') {
                    safeCnt++;
                } else {
                    unknownCnt++;
                }
            } else {
                displaySignatureError(file.name, result.error);
                unknownCnt++;
            }
            
        } catch (error) {
            console.error(`Signature analysis error for ${file.name}:`, error);
            displaySignatureError(file.name, error.message);
            unknownCnt++;
        }
    }
    
    // Update final statistics
    updateSignatureStats(safeCnt, threatCnt, unknownCnt);
    
    // Show results and hide loading
    showSignatureResults();
    showSignatureLoading(false);
    
    // Show completion notification
    const totalFiles = safeCnt + threatCnt + unknownCnt;
    showNotification(`Signature analysis complete! ${totalFiles} files processed, ${threatCnt} threats detected.`, 'success');
}

/**
 * Perform signature analysis on a single file
 * @param {File} file - File to analyze
 * @returns {Promise<Object>} Analysis result
 */
async function performSignatureAnalysis(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    return await makeApiRequest(API_ENDPOINTS.SIGNATURE_TEST, {
        method: 'POST',
        body: formData
    });
}

// ========================================
// SIGNATURE UI FUNCTIONS
// ========================================

/**
 * Show/hide signature loading screen
 * @param {boolean} show - Whether to show loading
 */
function showSignatureLoading(show) {
    if (signatureLoading) {
        signatureLoading.style.display = show ? 'flex' : 'none';
    }
    
    if (signatureScanButton) {
        signatureScanButton.disabled = show;
    }
    
    if (signatureClearButton) {
        signatureClearButton.disabled = show;
    }
}

/**
 * Update signature analysis progress
 * @param {number} current - Current file number
 * @param {number} total - Total files
 * @param {string} fileName - Current file name
 */
function updateSignatureProgress(current, total, fileName) {
    // Get the DOM elements
    const progressBarElement = document.getElementById('signature-progress-fill');
    const statusTextElement = document.getElementById('signature-loading-text');
    const currentFileElement = document.getElementById('signature-current-file');
    
    // Use the core utility function
    updateProgressBar(
        progressBarElement,           // The colored progress bar
        statusTextElement,           // The status text
        current,                     // Current file number
        total,                       // Total files
        '<i class="fas fa-cloud"></i> VirusTotal Lookup'  // Message
    );
    
    // Update current file info separately
    if (currentFileElement) {
        currentFileElement.innerHTML = `<i class="fas fa-fingerprint"></i> Checking: ${fileName}`;
    }
}

/**
 * Update signature statistics display
 * @param {number} safeCnt - Number of safe files
 * @param {number} threatCnt - Number of threats
 * @param {number} unknownCnt - Number of unknown files
 */
function updateSignatureStats(safeCnt, threatCnt, unknownCnt) {
    if (signatureTotalScanned) {
        signatureTotalScanned.textContent = safeCnt + threatCnt + unknownCnt;
    }
    if (signatureSafeCount) {
        signatureSafeCount.textContent = safeCnt;
    }
    if (signatureThreatCount) {
        signatureThreatCount.textContent = threatCnt;
    }
    if (signatureUnknownCount) {
        signatureUnknownCount.textContent = unknownCnt;
    }
}

/**
 * Show signature results container
 */
function showSignatureResults() {
    if (signatureResultsContainer) {
        signatureResultsContainer.style.display = 'block';
    }
}

/**
 * Clear signature results area
 */
function clearSignatureResultsArea() {
    if (signatureResultsArea) {
        signatureResultsArea.innerHTML = '';
    }
}

// ========================================
// SIGNATURE RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Display signature analysis result
 * @param {string} fileName - Name of the analyzed file
 * @param {Object} result - Analysis result data
 */
function displaySignatureResult(fileName, result) {
    const resultCard = document.createElement('div');
    resultCard.className = `result-card ${getSignatureResultClass(result.decision)}`;
    
    const confidence = (result.confidence * 100).toFixed(1);
    const badgeClass = getSignatureResultClass(result.decision);
    const badgeText = getSignatureBadgeText(result.decision);
    const badgeIcon = getSignatureBadgeIcon(result.decision);
    
    resultCard.innerHTML = `
        <div class="result-header">
            <h3>${fileName}</h3>
            <div class="result-badge ${badgeClass}">
                <i class="fas ${badgeIcon}"></i>
                ${badgeText} (${confidence}%)
            </div>
        </div>
        <div class="result-body">
            <div class="signature-section">
                <h5><i class="fas fa-fingerprint"></i> Signature Analysis</h5>
                <div class="hash-display">
                    <strong>SHA256:</strong> <code>${result.file_hash || 'Not available'}</code>
                </div>
                <div class="analysis-details">
                    <div class="detail-item">
                        <span class="detail-label">Decision:</span>
                        <span class="detail-value">${result.decision}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Confidence:</span>
                        <span class="detail-value">${confidence}%</span>
                    </div>
                </div>
                ${generateDetectionStatsSection(result)}
                <div style="margin-top: 1rem; padding: 0.75rem; background: #f8f9fa; border-radius: 6px;">
                    <strong>Reason:</strong> ${result.reason}
                </div>
            </div>
        </div>
    `;
    debugDetectionBar();
    signatureResultsArea.appendChild(resultCard);
}

/**
 * Generate detection statistics section
 * @param {Object} result - Analysis result
 * @returns {string} HTML for detection stats
 */
function generateDetectionStatsSection(result) {
    console.log('🔍 DEBUG: generateDetectionStatsSection called with:', result);
    
    if (!result.ratios || Object.keys(result.ratios).length === 0) {
        console.log('❌ DEBUG: No ratios found in result');
        return `
            <div style="margin-top: 1rem;">
                <strong><i class="fas fa-chart-bar"></i> Detection Statistics:</strong>
                <div class="vt-detection-bar" style="position: relative; height: 20px; background-color: #e3f2fd; border-radius: 10px; margin-top: 0.5rem; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);">
                    <div class="vt-detection-level" style="width: 0%; height: 100%; background: #4caf50; border-radius: 10px; transition: width 0.3s ease;"></div>
                    <div class="vt-detection-text" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 0.75rem; font-weight: 600; color: white; text-shadow: 0 1px 2px rgba(0, 0, 0, 0.7); z-index: 10;">
                        No data available
                    </div>
                </div>
                <small style="color: #666; font-size: 0.85rem; margin-top: 0.5rem; display: block;">
                    Detection data not available
                </small>
            </div>
        `;
    }
    
    console.log('📊 DEBUG: Ratios found:', result.ratios);
    
    const malwareRatio = (result.ratios.malware_ratio * 100).toFixed(1);
    const coverageRatio = (result.ratios.coverage_ratio * 100).toFixed(1);
    const cleanRatio = (result.ratios.clean_ratio * 100).toFixed(1);
    
    console.log('📈 DEBUG: Calculated values:', { malwareRatio, coverageRatio, cleanRatio });
    
    // FIXED: Always show the dominant result, not just malware
    const malwarePercent = parseFloat(malwareRatio);
    const cleanPercent = parseFloat(cleanRatio);
    
    // Determine what to display based on the actual decision
    let barColor, barWidth, displayText;
    
    if (result.decision === 'malicious') {
        // For malicious files, show the malware percentage
        barColor = '#f44336'; // Red
        barWidth = malwarePercent;
        displayText = `${malwareRatio}% detected as malware`;
    } else if (result.decision === 'benign') {
        // For benign files, show the clean percentage
        barColor = '#4caf50'; // Green
        barWidth = cleanPercent;
        displayText = `${cleanRatio}% clean`;
    } else {
        // For unknown files, show neutral
        barColor = '#ff9800'; // Orange
        barWidth = 50;
        displayText = 'Unknown status';
    }
    
    console.log('🎨 DEBUG: Bar display values:', { 
        decision: result.decision, 
        barColor, 
        barWidth, 
        displayText 
    });
    
    return `
        <div style="margin-top: 1rem;">
            <strong><i class="fas fa-chart-bar"></i> Detection Statistics:</strong>
            <div class="vt-detection-bar" style="position: relative; height: 20px; background-color: #e3f2fd; border-radius: 10px; margin-top: 0.5rem; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);">
                <div class="vt-detection-level" style="width: ${barWidth}%; height: 100%; background: ${barColor}; border-radius: 10px; transition: width 0.3s ease; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);"></div>
                <div class="vt-detection-text" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 0.75rem; font-weight: 600; color: white; text-shadow: 0 1px 2px rgba(0, 0, 0, 0.7); z-index: 10; white-space: nowrap;">
                    ${displayText}
                </div>
            </div>
            <small style="color: #666; font-size: 0.85rem; margin-top: 0.5rem; display: block;">
                Coverage: ${coverageRatio}% | Clean: ${cleanRatio}% | Malware: ${malwareRatio}%
            </small>
        </div>
    `;
}

function debugDetectionBar() {
    setTimeout(() => {
        const bars = document.querySelectorAll('.vt-detection-bar');
        console.log('🔍 Found', bars.length, 'detection bars');
        bars.forEach((bar, i) => {
            const level = bar.querySelector('.vt-detection-level');
            console.log(`Bar ${i}:`, { 
                barWidth: bar.style.width, 
                levelWidth: level?.style.width,
                levelBackground: level?.style.background 
            });
        });
    }, 500);
}

/**
 * Display signature analysis error
 * @param {string} fileName - Name of the file
 * @param {string} errorMessage - Error message
 */
function displaySignatureError(fileName, errorMessage) {
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
                <strong><i class="fas fa-bug"></i> Error:</strong> ${errorMessage}
            </div>
        </div>
    `;
    
    signatureResultsArea.appendChild(resultCard);
}

// ========================================
// SIGNATURE HELPER FUNCTIONS
// ========================================

/**
 * Get CSS class for signature result
 * @param {string} decision - Analysis decision
 * @returns {string} CSS class name
 */
function getSignatureResultClass(decision) {
    switch (decision) {
        case 'benign': return 'result-safe';
        case 'malicious': return 'result-threat';
        default: return 'result-unknown';
    }
}

/**
 * Get badge text for signature result
 * @param {string} decision - Analysis decision
 * @returns {string} Badge text
 */
function getSignatureBadgeText(decision) {
    switch (decision) {
        case 'benign': return 'Clean';
        case 'malicious': return 'Threat';
        default: return 'Unknown';
    }
}

/**
 * Get badge icon for signature result
 * @param {string} decision - Analysis decision
 * @returns {string} FontAwesome icon class
 */
function getSignatureBadgeIcon(decision) {
    switch (decision) {
        case 'benign': return 'fa-shield-alt';
        case 'malicious': return 'fa-exclamation-triangle';
        default: return 'fa-question-circle';
    }
}

// ========================================
// TOOLTIP FUNCTIONALITY
// ========================================

/**
 * Add tooltips to signature results
 */
function addSignatureTooltips() {
    const signatureResults = document.querySelectorAll('.signature-section');
    
    signatureResults.forEach(section => {
        const statsText = section.querySelector('small');
        if (statsText && statsText.textContent.includes('Coverage:')) {
            
            const tooltips = {
                'Coverage': 'Percentage of antivirus engines that successfully analyzed the file (excluding timeouts, failures, and unsupported formats)',
                'Clean': 'Percentage of engines that marked the file as harmless or benign with no threats detected'
            };
            
            let newText = statsText.innerHTML;
            
            Object.entries(tooltips).forEach(([term, definition]) => {
                const regex = new RegExp(`${term}:`, 'g');
                newText = newText.replace(regex, `<span class="tooltip" data-tooltip="${definition}">${term}:</span>`);
            });
            
            statsText.innerHTML = newText;
        }
    });
}

// ========================================
// INITIALIZATION AND EVENT HANDLING
// ========================================

/**
 * Initialize signature page when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the signature page by looking for signature-specific elements
    if (signatureUploadArea || signatureFileInput) {
        initializeSignaturePage();
    }
});

/**
 * Set up mutation observer for tooltips
 */
document.addEventListener('DOMContentLoaded', function() {
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1 && 
                        (node.classList.contains('result-card') || 
                         node.querySelector('.signature-section'))) {
                        setTimeout(addSignatureTooltips, 50);
                    }
                });
            }
        });
    });
    
    if (signatureResultsArea) {
        observer.observe(signatureResultsArea, {
            childList: true,
            subtree: true
        });
    }
});

// ========================================
// EXPORTS
// ========================================

export {
    initializeSignaturePage,
    scanSignatureFiles,
    clearSignatureFiles,
    displaySignatureResult,
    displaySignatureError,
    signatureFilesToScan,
    signatureScanResults,
    generateDetectionStatsSection
};

window.displaySignatureResult = displaySignatureResult;
// Add this after the existing exports section
window.displaySignatureResult = displaySignatureResult;
window.generateDetectionStatsSection = generateDetectionStatsSection;

console.log('✅ signature.js loaded - Signature Analysis Module Ready');