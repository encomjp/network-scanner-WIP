/**
 * Utility functions for the discovery page
 */

/**
 * Format a timestamp for display
 * @param {string} timestamp - ISO timestamp string
 * @return {string} Formatted date string
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Show an alert message to the user
 * @param {string} message - The message to display
 * @param {string} type - The alert type (success, danger, warning, info)
 */
function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    
    // Set message
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Add to the page
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) {
        // Create container if it doesn't exist
        const container = document.createElement('div');
        container.id = 'alert-container';
        container.className = 'my-3';
        
        // Find where to insert
        const scanSettings = document.querySelector('.card');
        scanSettings.parentNode.insertBefore(container, scanSettings);
    }
    
    // Add the alert
    document.getElementById('alert-container').appendChild(alertDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 150);
    }, 5000);
}

/**
 * Merge device lists without duplicates
 * @param {Array} existingDevices - Array of existing device objects
 * @param {Array} newDevices - Array of new device objects to merge
 * @return {Array} Merged array of device objects
 */
function mergeDevices(existingDevices, newDevices) {
    // Create a map of existing devices by IP
    const deviceMap = {};
    existingDevices.forEach(device => {
        deviceMap[device.ip] = device;
    });
    
    // Add or update with new devices
    newDevices.forEach(device => {
        // If the device is newer, update it
        if (!deviceMap[device.ip] || new Date(device.timestamp) > new Date(deviceMap[device.ip].timestamp)) {
            deviceMap[device.ip] = device;
        }
    });
    
    // Convert back to array
    return Object.values(deviceMap);
}

/**
 * Switch to a suggested network
 * @param {string} network - The network to use (e.g., 192.168.1.0/24)
 * @param {number} customTimeout - Optional custom timeout value
 */
function trySuggestedNetwork(network, customTimeout) {
    document.getElementById('target').value = network;
    if (customTimeout) {
        document.getElementById('timeout').value = customTimeout;
    }
    document.getElementById('scan-button').click();
}

/**
 * Use the selected network
 * @param {string} network - The network to set in the target field
 */
function useNetwork(network) {
    document.getElementById('target').value = network;
}