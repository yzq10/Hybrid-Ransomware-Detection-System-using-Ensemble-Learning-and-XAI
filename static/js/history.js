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
                            <td><button class="btn-small" onclick="viewDetails(${item.id})"><i class="fas fa-search"></i> View Details</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
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