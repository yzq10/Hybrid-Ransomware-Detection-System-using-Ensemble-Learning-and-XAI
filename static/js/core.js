// ========================================
// CORE.JS - Shared Utilities and API Endpoints
// ========================================
// This file contains all shared functionality used across multiple analysis modules

// ========================================
// API CONFIGURATION
// ========================================

const API_BASE_URL = '';

// UPDATED: API endpoints with corrected naming from cleaned api.py
export const API_ENDPOINTS = {
    HEALTH: `${API_BASE_URL}/api/health`,
    SCAN: `${API_BASE_URL}/api/scan`,
    MODEL_INFO: `${API_BASE_URL}/api/model/info`,
    SIGNATURE_TEST: `${API_BASE_URL}/api/signature-test`,
    STATIC_ANALYSIS: `${API_BASE_URL}/api/static-analysis`,  // Updated from /static-only
    DYNAMIC_ANALYSIS: `${API_BASE_URL}/api/dynamic-analysis`,
    CUCKOO_STATUS: `${API_BASE_URL}/api/cuckoo-status`
};

// ========================================
// COMMON UTILITY FUNCTIONS
// ========================================

/**
 * Format file size for display
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
export function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Show notification to user
 * @param {string} message - Notification message
 * @param {string} type - Notification type ('info', 'success', 'error')
 */
export function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 90px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 10px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        max-width: 400px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        background: ${type === 'error' ? '#f44336' : type === 'success' ? '#4caf50' : '#1976d2'};
        animation: slideIn 0.3s ease;
    `;
    
    const icon = type === 'error' ? 'fa-exclamation-circle' : 
                 type === 'success' ? 'fa-check-circle' : 'fa-info-circle';
    
    notification.innerHTML = `<i class="fas ${icon}"></i> ${message}`;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

/**
 * Validate file type and size
 * @param {File} file - File to validate
 * @returns {Object} Validation result with success boolean and message
 */
export function validateFile(file) {
    // Check file extension
    const extension = file.name.split('.').pop().toLowerCase();
    const allowedExtensions = ['exe', 'dll', 'sys'];
    
    if (!allowedExtensions.includes(extension)) {
        return {
            success: false,
            message: `${file.name} is not a supported file type. Only .exe, .dll, and .sys files are allowed.`
        };
    }
    
    // Check file size (1GB limit)
    const maxSize = 1024 * 1024 * 1024; // 1GB
    if (file.size > maxSize) {
        return {
            success: false,
            message: `${file.name} exceeds the maximum file size of 1GB.`
        };
    }
    
    return {
        success: true,
        message: 'File validation passed'
    };
}

/**
 * Safe access to individual models in analysis results
 * @param {Object} obj - Object potentially containing individual_models
 * @returns {Object} Individual models object or empty object
 */
export function safeGetIndividualModels(obj) {
    try {
        if (!obj || typeof obj !== 'object') return {};
        if (!obj.individual_models || typeof obj.individual_models !== 'object') return {};
        return obj.individual_models;
    } catch (e) {
        console.error('Safe access failed:', e);
        return {};
    }
}

/**
 * Make API request with error handling
 * @param {string} url - API endpoint URL
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} API response
 */
export async function makeApiRequest(url, options = {}) {
    try {
        const response = await fetch(url, options);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
        }
        
        return {
            success: true,
            data: data,
            response: response
        };
    } catch (error) {
        console.error(`API request failed for ${url}:`, error);
        return {
            success: false,
            error: error.message,
            data: null
        };
    }
}

// ========================================
// SHARED FILE HANDLING FUNCTIONS
// ========================================

/**
 * Setup drag and drop functionality for an upload area
 * @param {HTMLElement} uploadArea - Upload area element
 * @param {Function} handleFilesCallback - Callback function to handle dropped files
 */
export function setupDragAndDrop(uploadArea, handleFilesCallback) {
    if (!uploadArea) return;
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        handleFilesCallback(e.dataTransfer.files);
    });
}

/**
 * Setup file input and upload area click functionality
 * @param {HTMLElement} uploadArea - Upload area element
 * @param {HTMLElement} fileInput - File input element
 * @param {Function} handleFilesCallback - Callback function to handle selected files
 */
export function setupFileInput(uploadArea, fileInput, handleFilesCallback) {
    if (!uploadArea || !fileInput) return;
    
    uploadArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (event) => {
        handleFilesCallback(event.target.files);
    });
}

/**
 * Process and validate multiple files
 * @param {FileList} fileList - List of files to process
 * @param {Array} existingFiles - Array of already selected files
 * @returns {Object} Result with valid files and any error messages
 */
export function processFiles(fileList, existingFiles = []) {
    const validFiles = [];
    const errors = [];
    
    for (let file of fileList) {
        const validation = validateFile(file);
        
        if (!validation.success) {
            errors.push(validation.message);
            continue;
        }
        
        // Check if file already exists in the list
        const isDuplicate = existingFiles.some(f => 
            f.name === file.name && f.size === file.size
        );
        
        if (!isDuplicate) {
            validFiles.push(file);
        }
    }
    
    return {
        validFiles,
        errors
    };
}

// ========================================
// SHARED UI FUNCTIONS
// ========================================

/**
 * Update progress bar and status display
 * @param {HTMLElement} progressBar - Progress bar element
 * @param {HTMLElement} statusText - Status text element
 * @param {number} current - Current progress value
 * @param {number} total - Total progress value
 * @param {string} message - Progress message
 */
export function updateProgressBar(progressBar, statusText, current, total, message) {
    if (progressBar) {
        const progress = (current / total) * 100;
        progressBar.style.width = `${progress}%`;
    }
    
    if (statusText) {
        statusText.innerHTML = `${message} (${current}/${total})`;
    }
}

/**
 * Create and display file list
 * @param {Array} files - Array of files to display
 * @param {HTMLElement} container - Container element for file list
 * @param {Function} removeCallback - Callback function when file is removed
 */
export function displayFileList(files, container, removeCallback) {
    if (!container) return;
    
    if (files.length > 0) {
        container.style.display = 'block';
        const listElement = container.querySelector('ul') || container.querySelector('.file-list');
        
        if (listElement) {
            listElement.innerHTML = '';
            
            files.forEach((file, index) => {
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
                removeButton.addEventListener('click', () => removeCallback(index));
                
                li.appendChild(nameSpan);
                li.appendChild(removeButton);
                listElement.appendChild(li);
            });
        }
    } else {
        container.style.display = 'none';
    }
}

/**
 * Toggle visibility of collapsible sections
 * @param {HTMLElement} headerElement - Header element that was clicked
 */
export function toggleCollapsibleSection(headerElement) {
    const content = headerElement.nextElementSibling;
    const icon = headerElement.querySelector('.toggle-icon');
    
    if (content && icon) {
        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.style.transform = 'rotate(180deg)';
            icon.classList.remove('fa-chevron-down');
            icon.classList.add('fa-chevron-up');
        } else {
            content.style.display = 'none';
            icon.style.transform = 'rotate(0deg)';
            icon.classList.remove('fa-chevron-up');
            icon.classList.add('fa-chevron-down');
        }
    }
}

// ========================================
// SHARED NAVIGATION FUNCTIONS
// ========================================

/**
 * Initialize navigation functionality
 */
export function initializeNavigation() {
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    const navLinks = document.querySelectorAll('.nav-link');
    const contentSections = document.querySelectorAll('.content-section');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            navToggle.classList.toggle('active');
        });
    }

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Remove active class from all links
            navLinks.forEach(l => l.classList.remove('active'));
            
            // Add active class to clicked link
            link.classList.add('active');
            
            // Hide all sections
            contentSections.forEach(section => section.classList.remove('active'));
            
            // Show target section
            const targetSection = link.getAttribute('data-section') + '-section';
            const section = document.getElementById(targetSection);
            if (section) {
                section.classList.add('active');
            }
            
            // Close mobile menu
            if (navMenu) navMenu.classList.remove('active');
            if (navToggle) navToggle.classList.remove('active');
        });
    });
    
    let lastScrollTop = 0;
    const navbar = document.querySelector('.navbar');
    
    if (navbar) {
        window.addEventListener('scroll', () => {
            const currentScrollTop = window.pageYOffset || document.documentElement.scrollTop;
            
            if (currentScrollTop > lastScrollTop && currentScrollTop > 100) {
                // Scrolling down & past 100px - hide navbar
                navbar.style.transform = 'translateY(-100%)';
                navbar.style.transition = 'transform 0.3s ease-in-out';
            } else {
                // Scrolling up - show navbar
                navbar.style.transform = 'translateY(0)';
                navbar.style.transition = 'transform 0.3s ease-in-out';
            }
            
            lastScrollTop = currentScrollTop;
        });
    }
}



// ========================================
// SHARED RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Determine actual prediction value (handles contradictions in ensemble results)
 * @param {Object} analysisData - Analysis result data
 * @returns {number} Prediction value (0 or 1)
 */

export function determineActualPrediction(analysisData) {
    // TRUST THE BACKEND ENSEMBLE VOTING - Don't override it!
    
    // For dynamic analysis, use the prediction directly from backend
    if (analysisData.prediction !== undefined) {
        return parseInt(analysisData.prediction) || 0;
    }
    
    // Fallback
    return 0;
}

// export function determineActualPrediction(analysisData) {
//     let officialPrediction = 0;
//     if (analysisData.raw_prediction !== undefined) {
//         officialPrediction = analysisData.raw_prediction;
//     } else if (analysisData.prediction === 1 || analysisData.prediction === 'ransomware') {
//         officialPrediction = 1;
//     } else if (analysisData.prediction_label && analysisData.prediction_label.toLowerCase().includes('ransomware')) {
//         officialPrediction = 1;
//     }

//     // Check ensemble votes for contradictions
//     if (analysisData.explanation && analysisData.explanation.individual_models) {
//         const models = analysisData.explanation.individual_models;
//         const ransomwareVotes = Object.values(models).filter(model => model.prediction === 1).length;
//         const benignVotes = Object.values(models).filter(model => model.prediction === 0).length;
//         const ensembleVote = ransomwareVotes > benignVotes ? 1 : 0;
        
//         if (officialPrediction !== ensembleVote) {
//             console.log('🔥 CONTRADICTION: Using ensemble vote for color');
//             return ensembleVote;
//         }
//     }
    
//     return officialPrediction;
// }

/**
 * Get appropriate icon for model type
 * @param {string} modelName - Name of the model
 * @returns {string} FontAwesome icon class
 */
export function getModelIcon(modelName) {
    const icons = {
        'svm': 'balance-scale',
        'randomforest': 'tree',
        'random_forest': 'tree',
        'xgboost': 'bolt',
        'ensemble': 'brain'
    };
    return icons[modelName.toLowerCase()] || 'cog';
}

/**
 * Format analysis mode for display
 * @param {string} mode - Analysis mode string
 * @returns {string} Formatted mode string
 */
export function formatAnalysisMode(mode) {
    const modes = {
        'signature_only': 'Signature Analysis Only',
        'signature_static': 'Signature + Static Analysis',
        'full_3_stage': 'Full 3-Stage Pipeline',
        'static_only': 'Static Analysis Only',
        'dynamic_only': 'Dynamic Analysis Only'
    };
    return modes[mode] || mode;
}

// ========================================
// CSS ANIMATIONS
// ========================================

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { opacity: 0; transform: translateX(20px); }
        to { opacity: 1; transform: translateX(0); }
    }
    
    @keyframes fadeOut {
        from { opacity: 1; transform: translateX(0); }
        to { opacity: 0; transform: translateX(20px); }
    }
`;
document.head.appendChild(style);

// ========================================
// INITIALIZATION
// ========================================

// Initialize navigation when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
});

console.log('✅ core.js loaded - Shared utilities ready');