const API_BASE_URL = 'http://localhost:5000/api';

// File input handlers
document.getElementById('encryptFile').addEventListener('change', function(e) {
    const fileName = e.target.files[0]?.name || '';
    document.getElementById('encryptFileName').textContent = fileName;
});

document.getElementById('decryptFile').addEventListener('change', async function(e) {
    const fileName = e.target.files[0]?.name || '';
    document.getElementById('decryptFileName').textContent = fileName;
    
    // Detect algorithm if file is selected
    if (e.target.files[0]) {
        await detectEncryptionAlgorithm(e.target.files[0]);
    } else {
        // Reset to auto-detect if no file
        document.getElementById('decryptAlgorithm').value = 'auto';
        document.getElementById('decryptAlgorithmHint').style.display = 'none';
    }
});

// Drag and drop handlers
setupDragAndDrop('encryptUploadArea', 'encryptFile');
setupDragAndDrop('decryptUploadArea', 'decryptFile');

function setupDragAndDrop(areaId, inputId) {
    const area = document.getElementById(areaId);
    const input = document.getElementById(inputId);
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.add('dragover'), false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.remove('dragover'), false);
    });
    
    area.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        input.files = files;
        
        const fileName = files[0]?.name || '';
        if (areaId === 'encryptUploadArea') {
            document.getElementById('encryptFileName').textContent = fileName;
        } else {
            document.getElementById('decryptFileName').textContent = fileName;
            // Detect algorithm for decryption file
            if (files[0]) {
                detectEncryptionAlgorithm(files[0]);
            } else {
                document.getElementById('decryptAlgorithm').value = 'auto';
                document.getElementById('decryptAlgorithmHint').style.display = 'none';
            }
        }
    }, false);
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
}

async function encryptFile() {
    const fileInput = document.getElementById('encryptFile');
    const passwordInput = document.getElementById('encryptPassword');
    const messageDiv = document.getElementById('encryptMessage');
    const btn = event.target.closest('.btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');
    
    // Validation
    if (!fileInput.files[0]) {
        showMessage(messageDiv, 'Please select a file to encrypt', 'error');
        return;
    }
    
    if (!passwordInput.value || passwordInput.value.length < 8) {
        showMessage(messageDiv, 'Password must be at least 8 characters', 'error');
        return;
    }
    
    // Show loading state
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';
    messageDiv.classList.remove('show');
    
    try {
        const algorithmInput = document.getElementById('encryptAlgorithm');
        const selectedAlgorithm = algorithmInput.value;
        
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('password', passwordInput.value);
        formData.append('algorithm', selectedAlgorithm);
        
        const response = await fetch(`${API_BASE_URL}/encrypt`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Encryption failed');
        }
        
        // Download the encrypted file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileInput.files[0].name + '.enc';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        const algorithmName = algorithmInput.options[algorithmInput.selectedIndex].text.split('(')[0].trim();
        showMessage(messageDiv, `File encrypted successfully using ${algorithmName}! Download started.`, 'success');
        
        // Reset form
        fileInput.value = '';
        passwordInput.value = '';
        document.getElementById('encryptFileName').textContent = '';
        
    } catch (error) {
        showMessage(messageDiv, error.message, 'error');
    } finally {
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
}

async function decryptFile() {
    const fileInput = document.getElementById('decryptFile');
    const passwordInput = document.getElementById('decryptPassword');
    const algorithmInput = document.getElementById('decryptAlgorithm');
    const messageDiv = document.getElementById('decryptMessage');
    const btn = event.target.closest('.btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');
    
    // Validation
    if (!fileInput.files[0]) {
        showMessage(messageDiv, 'Please select an encrypted file (.enc)', 'error');
        return;
    }
    
    if (!passwordInput.value) {
        showMessage(messageDiv, 'Please enter the decryption password', 'error');
        return;
    }
    
    // Show loading state
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';
    messageDiv.classList.remove('show');
    
    try {
        const selectedAlgorithm = algorithmInput.value;
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('password', passwordInput.value);
        
        // If manual algorithm is selected (not auto), send it
        // Note: Backend will still auto-detect, but this allows for future manual override
        if (selectedAlgorithm !== 'auto') {
            formData.append('algorithm', selectedAlgorithm);
        }
        
        const response = await fetch(`${API_BASE_URL}/decrypt`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Decryption failed');
        }
        
        // Download the decrypted file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        // Get original filename from response headers or derive from encrypted filename
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = fileInput.files[0].name.replace('.enc', '');
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
            if (filenameMatch) {
                filename = filenameMatch[1];
            }
        }
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showMessage(messageDiv, 'File decrypted successfully! Download started.', 'success');
        
        // Reset form
        fileInput.value = '';
        passwordInput.value = '';
        document.getElementById('decryptFileName').textContent = '';
        document.getElementById('decryptAlgorithm').value = 'auto';
        document.getElementById('decryptAlgorithmHint').style.display = 'none';
        
    } catch (error) {
        showMessage(messageDiv, error.message, 'error');
    } finally {
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
}

async function detectEncryptionAlgorithm(file) {
    try {
        // Read first few bytes to detect algorithm without sending full file
        const reader = new FileReader();
        reader.onload = async function(e) {
            const arrayBuffer = e.target.result;
            const bytes = new Uint8Array(arrayBuffer);
            
            // We need at least 18 bytes: 1 (algo) + 16 (salt) + 1 (iv)
            if (bytes.length < 18) {
                document.getElementById('decryptAlgorithm').value = 'auto';
                document.getElementById('decryptAlgorithmHint').style.display = 'none';
                return;
            }
            
            const algorithmId = bytes[0];
            
            // Map algorithm IDs to algorithm values (matching backend)
            const algorithmIdMap = {
                1: 'aes-128-cbc',
                2: 'aes-192-cbc',
                3: 'aes-256-cbc',
                4: 'aes-128-gcm',
                5: 'aes-192-gcm',
                6: 'aes-256-gcm',
                7: 'aes-128-ctr',
                8: 'aes-192-ctr',
                9: 'aes-256-ctr',
                10: 'aes-128-cfb',
                11: 'aes-192-cfb',
                12: 'aes-256-cfb',
                13: 'aes-128-ofb',
                14: 'aes-192-ofb',
                15: 'aes-256-ofb',
                16: 'chacha20'
            };
            
            const detectedAlgorithm = algorithmIdMap[algorithmId];
            if (detectedAlgorithm) {
                // Set the dropdown to detected algorithm
                const algorithmSelect = document.getElementById('decryptAlgorithm');
                algorithmSelect.value = detectedAlgorithm;
                
                // Show hint with algorithm name
                const algorithmNames = {
                    'aes-128-cbc': 'AES-128-CBC',
                    'aes-192-cbc': 'AES-192-CBC',
                    'aes-256-cbc': 'AES-256-CBC',
                    'aes-128-gcm': 'AES-128-GCM',
                    'aes-192-gcm': 'AES-192-GCM',
                    'aes-256-gcm': 'AES-256-GCM',
                    'aes-128-ctr': 'AES-128-CTR',
                    'aes-192-ctr': 'AES-192-CTR',
                    'aes-256-ctr': 'AES-256-CTR',
                    'aes-128-cfb': 'AES-128-CFB',
                    'aes-192-cfb': 'AES-192-CFB',
                    'aes-256-cfb': 'AES-256-CFB',
                    'aes-128-ofb': 'AES-128-OFB',
                    'aes-192-ofb': 'AES-192-OFB',
                    'aes-256-ofb': 'AES-256-OFB',
                    'chacha20': 'ChaCha20-Poly1305'
                };
                
                const hintDiv = document.getElementById('decryptAlgorithmHint');
                const hintText = document.getElementById('decryptAlgorithmHintText');
                hintText.textContent = `✓ Detected: ${algorithmNames[detectedAlgorithm]}`;
                hintDiv.style.display = 'block';
            } else {
                document.getElementById('decryptAlgorithm').value = 'auto';
                document.getElementById('decryptAlgorithmHint').style.display = 'none';
            }
        };
        
        // Read only first 20 bytes (enough to detect algorithm)
        const blob = file.slice(0, 20);
        reader.readAsArrayBuffer(blob);
        
    } catch (error) {
        console.error('Error detecting algorithm:', error);
        document.getElementById('decryptAlgorithm').value = 'auto';
        document.getElementById('decryptAlgorithmHint').style.display = 'none';
    }
}

function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `message show ${type}`;
    setTimeout(() => {
        element.classList.remove('show');
    }, 5000);
}

// Sandbox Analysis Functions
document.getElementById('sandboxFile').addEventListener('change', function(e) {
    const fileName = e.target.files[0]?.name || '';
    document.getElementById('sandboxFileName').textContent = fileName;
});

setupDragAndDrop('sandboxUploadArea', 'sandboxFile');

let currentAnalysisId = null;
let analysisPollInterval = null;

async function startAnalysis() {
    const fileInput = document.getElementById('sandboxFile');
    const timeoutInput = document.getElementById('sandboxTimeout');
    const messageDiv = document.getElementById('sandboxMessage');
    const resultsDiv = document.getElementById('analysisResults');
    const btn = event.target.closest('.btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');
    
    if (!fileInput.files[0]) {
        showMessage(messageDiv, 'Please select a file to analyze', 'error');
        return;
    }
    
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';
    messageDiv.classList.remove('show');
    resultsDiv.style.display = 'none';
    
    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('timeout', timeoutInput.value);
        
        const response = await fetch(`${API_BASE_URL}/sandbox/analyze`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Analysis failed to start');
        }
        
        const data = await response.json();
        currentAnalysisId = data.analysis_id;
        
        showMessage(messageDiv, 'Analysis started in sandbox. Monitoring behavior...', 'success');
        resultsDiv.style.display = 'block';
        
        // Start polling for logs
        startPollingLogs(currentAnalysisId);
        
    } catch (error) {
        showMessage(messageDiv, error.message, 'error');
    } finally {
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
}

function startPollingLogs(analysisId) {
    // Clear existing interval
    if (analysisPollInterval) {
        clearInterval(analysisPollInterval);
    }
    
    // Poll immediately
    fetchLogs(analysisId);
    
    // Then poll every 2 seconds
    analysisPollInterval = setInterval(() => {
        fetchLogs(analysisId);
    }, 2000);
    
    // Stop polling after 60 seconds
    setTimeout(() => {
        if (analysisPollInterval) {
            clearInterval(analysisPollInterval);
            analysisPollInterval = null;
        }
    }, 60000);
}

async function fetchLogs(analysisId) {
    try {
        const response = await fetch(`${API_BASE_URL}/sandbox/logs/${analysisId}`);
        if (response.ok) {
            const data = await response.json();
            updateLogsDisplay(data);
            
            // If analysis is complete, stop polling
            if (!data.is_active && analysisPollInterval) {
                clearInterval(analysisPollInterval);
                analysisPollInterval = null;
            }
        }
    } catch (error) {
        console.error('Error fetching logs:', error);
    }
}

function updateLogsDisplay(data) {
    const logsScroll = document.getElementById('logsScroll');
    const summaryDiv = document.getElementById('resultsSummary');
    
    // Clear existing logs (except template)
    const existingLogs = logsScroll.querySelectorAll('.log-entry:not(#logTemplate)');
    existingLogs.forEach(log => log.remove());
    
    // Add new logs
    if (data.logs && data.logs.length > 0) {
        data.logs.forEach(log => {
            const logEntry = document.getElementById('logTemplate').cloneNode(true);
            logEntry.id = '';
            logEntry.style.display = 'flex';
            
            const time = new Date(log.timestamp).toLocaleTimeString();
            logEntry.querySelector('.log-time').textContent = time;
            logEntry.querySelector('.log-category').textContent = log.category;
            logEntry.querySelector('.log-message').textContent = log.message;
            
            // Add category class
            const categoryClass = log.category.toLowerCase().replace('_', '-');
            logEntry.classList.add(categoryClass);
            
            logsScroll.appendChild(logEntry);
        });
        
        // Scroll to bottom
        logsScroll.scrollTop = logsScroll.scrollHeight;
        
        // Update summary
        const summary = {
            'Total Logs': data.logs.length,
            'File Changes': data.logs.filter(l => l.category.includes('FILE')).length,
            'Network Calls': data.logs.filter(l => l.category.includes('NETWORK')).length,
            'Processes': data.logs.filter(l => l.category.includes('PROCESS')).length
        };
        
        summaryDiv.innerHTML = Object.entries(summary).map(([label, value]) => `
            <div class="summary-item">
                <div class="summary-item-label">${label}</div>
                <div class="summary-item-value">${value}</div>
            </div>
        `).join('');
    }
}

function clearAnalysis() {
    const resultsDiv = document.getElementById('analysisResults');
    const logsScroll = document.getElementById('logsScroll');
    const summaryDiv = document.getElementById('resultsSummary');
    const messageDiv = document.getElementById('sandboxMessage');
    
    resultsDiv.style.display = 'none';
    logsScroll.innerHTML = '<div class="log-entry" id="logTemplate" style="display: none;"><span class="log-time"></span><span class="log-category"></span><span class="log-message"></span></div>';
    summaryDiv.innerHTML = '';
    messageDiv.classList.remove('show');
    
    if (analysisPollInterval) {
        clearInterval(analysisPollInterval);
        analysisPollInterval = null;
    }
    
    currentAnalysisId = null;
    document.getElementById('sandboxFile').value = '';
    document.getElementById('sandboxFileName').textContent = '';
}

// Check API health on load
window.addEventListener('load', async () => {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (!response.ok) {
            console.warn('Backend API is not responding. Make sure the server is running on port 5000.');
        }
    } catch (error) {
        console.warn('Cannot connect to backend API. Make sure the server is running on port 5000.');
    }
});

