/**
 * Functions for displaying scan results in the discovery page
 */

/**
 * Display scan results in the table
 * @param {Array} devices - Array of device objects to display
 */
function displayResults(devices) {
    const tableBody = document.querySelector('#results-table tbody');
    
    // Clear previous content
    tableBody.innerHTML = '';
    
    // Check for empty results
    if (!devices || devices.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No devices found.</td></tr>';
        console.log('No devices to display');
        return;
    }
    
    console.log(`Displaying ${devices.length} devices in the results table`);
    
    // Display each device in the table
    devices.forEach(device => {
        // Skip invalid devices
        if (!device || !device.ip) {
            console.warn('Skipping invalid device entry:', device);
            return;
        }
        
        const row = document.createElement('tr');
        
        // Get device status and corresponding badge class
        const status = device.status || 'unknown';
        let badgeClass = 'bg-secondary'; // Default gray
        
        if (status === 'up') {
            badgeClass = 'bg-success'; // Green for up
        } else if (status === 'down') {
            badgeClass = 'bg-danger'; // Red for down 
        } else if (status === 'pending') {
            badgeClass = 'bg-warning'; // Yellow for pending
        }
        
        // Format the timestamp
        const timestamp = formatTimestamp(device.timestamp);
        
        // Set the row content
        row.innerHTML = `
            <td>${device.ip}</td>
            <td><span class="badge ${badgeClass}">${status}</span></td>
            <td>${device.method || 'Unknown'}</td>
            <td>${timestamp}</td>
            <td>
                <div class="btn-group btn-group-sm" role="group">
                    <button type="button" class="btn btn-outline-primary scan-ports" data-ip="${device.ip}">
                        <i class="bi bi-hdd-network"></i>
                    </button>
                    <button type="button" class="btn btn-outline-info fingerprint" data-ip="${device.ip}">
                        <i class="bi bi-fingerprint"></i>
                    </button>
                    <button type="button" class="btn btn-outline-danger nmap-scan" data-ip="${device.ip}">
                        <i class="bi bi-shield-check"></i>
                    </button>
                </div>
            </td>
        `;
        
        // Add the row to the table
        tableBody.appendChild(row);
    });
    
    // Add event listeners to action buttons
    setupActionButtonListeners();
}

/**
 * Setup event listeners for the action buttons in the results table
 */
function setupActionButtonListeners() {
    // Port Scanning buttons
    document.querySelectorAll('.scan-ports').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            window.location.href = `/services?target=${ip}`;
        });
    });
    
    // Fingerprinting buttons
    document.querySelectorAll('.fingerprint').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            window.location.href = `/fingerprint?target=${ip}`;
        });
    });
    
    // Nmap scan buttons
    document.querySelectorAll('.nmap-scan').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            window.location.href = `/nmap?target=${ip}`;
        });
    });
}

/**
 * Update the scan status display
 * 
 * @param {string} status - Status message
 * @param {number} progress - Progress percentage (0-100)
 * @param {number} elapsed - Elapsed time in seconds
 * @param {number} deviceCount - Number of devices found
 */
function updateScanStatus(status, progress = null, elapsed = null, deviceCount = null) {
    const scanStatus = document.getElementById('scan-status');
    scanStatus.classList.remove('d-none');
    
    let statusHTML = `
        <div class="d-flex align-items-center">
            <div class="spinner-border spinner-border-sm me-2" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <div>${status}</div>
        </div>
    `;
    
    // Add progress bar if provided
    if (progress !== null) {
        const progressPercent = Math.min(99, Math.round(progress));
        statusHTML += `
            <div class="progress" style="height: 5px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                     role="progressbar" 
                     style="width: ${progressPercent}%" 
                     aria-valuenow="${progressPercent}" 
                     aria-valuemin="0" 
                     aria-valuemax="100">
                </div>
            </div>
        `;
    }
    
    scanStatus.innerHTML = statusHTML;
}

/**
 * Hide the scan status display
 */
function hideScanStatus() {
    const scanStatus = document.getElementById('scan-status');
    scanStatus.classList.add('d-none');
}

/**
 * Show empty results message in the table
 * @param {string} message - Message to display
 */
function showEmptyResults(message) {
    const tableBody = document.querySelector('#results-table tbody');
    tableBody.innerHTML = `<tr><td colspan="5" class="text-center">${message}</td></tr>`;
}

/**
 * Display network suggestions for when no devices are found
 * @param {string} target - The target that was scanned
 */
function displayNetworkSuggestions(target) {
    const tableBody = document.querySelector('#results-table tbody');
    
    // If the target was a single IP, suggest scanning the whole network
    if (target.endsWith('.254') || target.endsWith('.1')) {
        // Extract network from target
        const parts = target.split('.');
        if (parts.length === 4) {
            const suggestedNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
            
            // Add a button to try the suggested network
            const row = document.createElement('tr');
            row.innerHTML = `
                <td colspan="5" class="text-center">
                    <button type="button" class="btn btn-outline-primary mt-2" onclick="trySuggestedNetwork('${suggestedNetwork}')">
                        Try scanning ${suggestedNetwork}
                    </button>
                    <button type="button" class="btn btn-outline-secondary mt-2 ms-2" onclick="trySuggestedNetwork('${target}', 10.0)">
                        Try again with longer timeout
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
            return;
        }
    }
    
    // Show common network suggestions
    const row = document.createElement('tr');
    row.innerHTML = `
        <td colspan="5" class="text-center">
            <div class="mt-2">
                <button type="button" class="btn btn-outline-primary m-1" onclick="trySuggestedNetwork('192.168.1.0/24')">
                    Try 192.168.1.0/24
                </button>
                <button type="button" class="btn btn-outline-primary m-1" onclick="trySuggestedNetwork('192.168.0.0/24')">
                    Try 192.168.0.0/24
                </button>
                <button type="button" class="btn btn-outline-primary m-1" onclick="trySuggestedNetwork('192.168.31.0/24')">
                    Try 192.168.31.0/24
                </button>
                <button type="button" class="btn btn-outline-primary m-1" onclick="trySuggestedNetwork('192.168.22.0/24')">
                    Try 192.168.22.0/24
                </button>
            </div>
        </td>
    `;
    tableBody.appendChild(row);
}

// Export functions for use in main script
window.displayResults = displayResults;
window.updateScanStatus = updateScanStatus;
window.hideScanStatus = hideScanStatus;
window.showEmptyResults = showEmptyResults;
window.displayNetworkSuggestions = displayNetworkSuggestions;