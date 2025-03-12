/**
 * Network detection functionality for the discovery page
 */

/**
 * Detect the network automatically
 * Attempts to find the gateway and suggest the appropriate network
 */
function detectNetwork() {
    const networkInfo = document.getElementById('network-info');
    networkInfo.innerHTML = '<p>Detecting your network...</p>';
    
    // Use the new comprehensive network detection
    fetch('/api/network-info')
    .then(response => response.json())
    .then(data => {
        if (data.success && data.data) {
            const info = data.data;
            const defaultGateway = info.default_gateway ? info.default_gateway.ip : null;
            const recommendedTargets = info.recommended_targets || [];
            const interfaces = info.interfaces || [];
            
            // Build HTML content
            let content = '<h5>Network Information</h5>';
            
            // Show interfaces
            if (interfaces.length > 0) {
                content += '<div class="mb-3"><h6>Network Interfaces:</h6>';
                interfaces.forEach(iface => {
                    content += `
                        <div class="mb-2">
                            <strong>${iface.name}:</strong> ${iface.ip}
                            ${iface.network ? `(${iface.network})` : ''}
                        </div>
                    `;
                });
                content += '</div>';
            }
            
            // Show default gateway
            if (defaultGateway) {
                content += `
                    <div class="mb-3">
                        <h6>Default Gateway:</h6>
                        <div>${defaultGateway}</div>
                    </div>
                `;
            }
            
            // Show recommended targets
            if (recommendedTargets.length > 0) {
                content += '<div class="mb-3"><h6>Recommended Networks:</h6>';
                content += '<div class="btn-group btn-group-sm" role="group">';
                recommendedTargets.forEach(target => {
                    content += `
                        <button type="button" class="btn btn-outline-success" onclick="useNetwork('${target}')">
                            ${target}
                        </button>
                    `;
                });
                content += '</div></div>';
            }
            
            // Show nmap info if available
            if (info.nmap) {
                content += '<div class="mt-3"><h6>Additional Information:</h6>';
                Object.entries(info.nmap).forEach(([ip, data]) => {
                    if (data.os_info && data.os_info.name) {
                        content += `
                            <div class="mb-2">
                                <strong>${ip}:</strong> ${data.os_info.name}
                                ${data.os_info.accuracy ? ` (${data.os_info.accuracy}% confidence)` : ''}
                            </div>
                        `;
                    }
                });
                content += '</div>';
            }
            
            // If we have a default gateway network, suggest it first
            if (defaultGateway) {
                const parts = defaultGateway.split('.');
                if (parts.length === 4) {
                    const suggestedNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
                    // Set the target field
                    document.getElementById('target').value = suggestedNetwork;
                }
            }
            
            // Update the network info display
            networkInfo.innerHTML = content;
        } else {
            throw new Error(data.error || 'Could not detect network');
        }
    })
    .catch(error => {
        console.error('Error detecting network:', error);
        networkInfo.innerHTML = `
            <p class="text-danger">Error detecting network: ${error.message}</p>
            <p>Try one of these common networks:</p>
            <div class="btn-group btn-group-sm" role="group">
                <button type="button" class="btn btn-outline-primary" onclick="useNetwork('192.168.1.0/24')">192.168.1.0/24</button>
                <button type="button" class="btn btn-outline-primary" onclick="useNetwork('192.168.0.0/24')">192.168.0.0/24</button>
                <button type="button" class="btn btn-outline-primary" onclick="useNetwork('192.168.31.0/24')">192.168.31.0/24</button>
                <button type="button" class="btn btn-outline-primary" onclick="useNetwork('192.168.22.0/24')">192.168.22.0/24</button>
            </div>
        `;
    });
}

// Export functions for use in main script
window.detectNetwork = detectNetwork;
