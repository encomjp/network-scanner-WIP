/**
 * Main script for the discovery page
 */

// Initialize the discovery page when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initDiscoveryPage();
});

/**
 * Initialize the discovery page
 * Sets up event listeners and detects the network
 */
function initDiscoveryPage() {
    // Detect network on page load
    detectNetwork();
    
    // Set up event listeners
    setupEventListeners();
}

/**
 * Set up event listeners for page elements
 */
function setupEventListeners() {
    // Handle detect network button
    document.getElementById('detect-network').addEventListener('click', function() {
        detectNetwork();
    });
    
    // Handle form submission
    document.getElementById('discover-form').addEventListener('submit', function(event) {
        event.preventDefault();
        performScan();
    });
}

/**
 * Perform a network scan based on form values
 */
function performScan() {
    // Get form values
    const target = document.getElementById('target').value;
    const passive = document.getElementById('passive').checked;
    const stealth = document.getElementById('stealth').checked;
    const timeout = parseFloat(document.getElementById('timeout').value);
    
    // Clear previous results
    const tableBody = document.querySelector('#results-table tbody');
    tableBody.innerHTML = '<tr><td colspan="5" class="text-center">Scanning...</td></tr>';
    
    // Perform scan
    fetch('/api/discover', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            target: target,
            passive: passive,
            stealth: stealth,
            timeout: timeout
        })
    })
    .then(response => response.json())
    .then(data => {
        // Initial response received, but scan might still be in progress
        if (data.success) {
            // Start polling for results
            pollForResults(target, timeout);
        } else {
            // Hide scan status
            hideScanStatus();
            
            // Enable scan button
            document.getElementById('scan-button').disabled = false;
            
            // Show error
            tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Error starting scan.</td></tr>';
            showAlert('Error starting scan: ' + data.message, 'danger');
        }
    })
    .catch(error => {
        // Hide scan status
        hideScanStatus();
        
        // Enable scan button
        document.getElementById('scan-button').disabled = false;
        
        // Show error
        tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Error performing scan.</td></tr>';
        showAlert('Error performing scan: ' + error.message, 'danger');
        console.error('Error:', error);
    });
}