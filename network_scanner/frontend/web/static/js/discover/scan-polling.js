/**
 * Functions for polling scan results in the discovery page
 */

/**
 * Poll for scan results
 * @param {string} target - Target being scanned
 * @param {number} timeout - Scan timeout in seconds
 */
function pollForResults(target, timeout) {
    const scanButton = document.getElementById('scan-button');
    scanButton.disabled = true;
    
    // Update scan status message
    updateScanStatus(`Scanning ${target}... This may take a while for large networks.`);
    
    // Calculate polling interval based on timeout
    // For larger timeouts, we poll less frequently, but ensure we poll at least every second
    const pollInterval = Math.max(1000, Math.min(2000, timeout * 300));
    
    // Set a maximum polling duration (8x the timeout to give more time for results)
    const maxPollingDuration = timeout * 8000;
    const startTime = Date.now();
    
    // Create a cache to store found devices
    let deviceCache = [];
    
    // Track the number of consecutive empty results
    let emptyResultCount = 0;
    
    // Function to check for results
    function checkResults() {
        const elapsedTime = Math.round((Date.now() - startTime) / 1000);
        console.log(`Polling for results on ${target} (elapsed: ${elapsedTime}s)`);
        
        // Use the exact target that was entered by the user
        fetch('/api/discover', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                passive: false,
                stealth: false,
                timeout: 1.0  // Use a short timeout for polling
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('API response:', data);
            
            // Check if we have any results
            if (data.success && data.data && data.data.length > 0) {
                console.log(`Found ${data.data.length} devices in this poll`);
                emptyResultCount = 0; // Reset empty result counter
                
                // Update our device cache with new devices
                deviceCache = mergeDevices(deviceCache, data.data);
                console.log(`Total unique devices in cache: ${deviceCache.length}`);
                
                // Display the cached devices
                displayResults(deviceCache);
                
                // If we have devices, continue polling but show results
                const elapsedTime = Date.now() - startTime;
                if (elapsedTime < maxPollingDuration) {
                    // Continue polling to find more devices
                    setTimeout(checkResults, pollInterval);
                    
                    // Update status with progress but show we found devices
                    const progressPercent = Math.min(99, Math.round((elapsedTime / maxPollingDuration) * 100));
                    updateScanStatus(
                        `Found ${deviceCache.length} devices. Continuing scan... (${Math.round(elapsedTime / 1000)}s elapsed)`, 
                        progressPercent
                    );
                } else {
                    // Polling complete, show final results
                    hideScanStatus();
                    scanButton.disabled = false;
                    showAlert(`Scan complete. Found ${deviceCache.length} devices on ${target}.`, 'success');
                }
            } else {
                console.log('No new devices found in this poll');
                emptyResultCount++; // Increment empty result counter
                
                // If we're scanning 192.168.22.0/24, try a direct scan of that network
                trySpecialCaseNetworks(target, emptyResultCount);
                
                // No results yet, check if we should continue polling
                const elapsedTime = Date.now() - startTime;
                
                // If we have devices in cache, display them
                if (deviceCache.length > 0) {
                    console.log(`Displaying ${deviceCache.length} devices from cache`);
                    displayResults(deviceCache);
                    
                    if (elapsedTime < maxPollingDuration) {
                        // Continue polling to find more devices
                        setTimeout(checkResults, pollInterval);
                        
                        // Update status with progress
                        const progressPercent = Math.min(99, Math.round((elapsedTime / maxPollingDuration) * 100));
                        updateScanStatus(
                            `Found ${deviceCache.length} devices. Continuing scan... (${Math.round(elapsedTime / 1000)}s elapsed)`, 
                            progressPercent
                        );
                    } else {
                        // Polling complete, show final results
                        hideScanStatus();
                        scanButton.disabled = false;
                        showAlert(`Scan complete. Found ${deviceCache.length} devices on ${target}.`, 'success');
                    }
                } else if (elapsedTime < maxPollingDuration) {
                    // If we've had too many empty results in a row, poll less frequently
                    const nextPollDelay = emptyResultCount > 3 ? pollInterval * 1.5 : pollInterval;
                    
                    // Continue polling
                    setTimeout(checkResults, nextPollDelay);
                    
                    // Update loading message
                    const progressPercent = Math.min(99, Math.round((elapsedTime / maxPollingDuration) * 100));
                    updateScanStatus(`Scanning ${target}... (${Math.round(elapsedTime / 1000)}s elapsed)`, progressPercent);
                } else {
                    // Polling timeout reached
                    hideScanStatus();
                    scanButton.disabled = false;
                    
                    if (deviceCache.length === 0) {
                        showEmptyResults('No devices found or scan timed out.');
                        
                        // Try scanning the network directly instead of a single IP
                        if (target.endsWith('.254') || target.endsWith('.1')) {
                            // Extract network from target
                            const parts = target.split('.');
                            if (parts.length === 4) {
                                const suggestedNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
                                
                                // Suggest trying the network
                                showAlert(`No devices found for ${target}. Try scanning the entire network ${suggestedNetwork} instead.`, 'warning');
                                
                                // Add suggestions to the table
                                displayNetworkSuggestions(target);
                                return;
                            }
                        }
                        
                        // Suggest trying a different network
                        showAlert(`No devices found for ${target} after extended scanning. Try a different network or increase the timeout.`, 'warning');
                        
                        // Add suggestions to the table
                        displayNetworkSuggestions(target);
                    } else {
                        showAlert(`Scan complete. Found ${deviceCache.length} devices on ${target}.`, 'success');
                    }
                }
            }
        })
        .catch(error => {
            // Error during polling
            console.error('Error polling for results:', error);
            
            // If we have devices in cache, display them
            if (deviceCache.length > 0) {
                console.log(`Displaying ${deviceCache.length} devices from cache after error`);
                displayResults(deviceCache);
                hideScanStatus();
                scanButton.disabled = false;
                return;
            }
            
            // Check if we should continue polling despite the error
            const elapsedTime = Date.now() - startTime;
            if (elapsedTime < maxPollingDuration) {
                // Continue polling after a short delay
                setTimeout(checkResults, pollInterval);
            } else {
                // Polling timeout reached
                hideScanStatus();
                scanButton.disabled = false;
                showEmptyResults('Error retrieving scan results.');
                showAlert('Error retrieving scan results: ' + error.message, 'danger');
            }
        });
    }
    
    // Start polling after a short delay
    setTimeout(checkResults, 1000);
}

/**
 * Try special case networks when needed
 * @param {string} target - Target being scanned
 * @param {number} emptyResultCount - Number of empty results
 */
function trySpecialCaseNetworks(target, emptyResultCount) {
    // If we're scanning 192.168.22.0/24, try a direct scan of that network
    if (target.includes('192.168.22.0') && emptyResultCount === 3) {
        console.log('Trying direct scan of 192.168.22.0/24');
        fetch('/api/discover', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: '192.168.22.0/24',
                passive: false,
                stealth: false,
                timeout: 5.0  // Use a longer timeout for this specific scan
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data && data.data.length > 0) {
                console.log(`Direct scan found ${data.data.length} devices`);
                deviceCache = mergeDevices(deviceCache, data.data);
                displayResults(deviceCache);
            }
        })
        .catch(err => console.error('Error in direct scan:', err));
    }
}

// Export functions for use in main script
window.pollForResults = pollForResults;