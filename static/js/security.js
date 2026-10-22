/**
 * NexaVault Security & Forensics Client Script
 */

async function verifyAuditChain() {
    const resultBox = document.getElementById('chain-verify-result');
    if (!resultBox) return;
    
    resultBox.style.display = 'block';
    resultBox.innerHTML = `
        <div class="card" style="border-left: 4px solid #0288D1; background-color: #E1F5FE;">
            <strong>Forensic Integrity Scanner:</strong> Walking through sequential cryptographic SHA-256 links...
        </div>
    `;
    
    try {
        const response = await fetch('/api/audit/verify');
        const data = await response.json();
        
        if (data.is_valid) {
            resultBox.innerHTML = `
                <div class="card" style="border-left: 4px solid #2E7D32; background-color: #E8F5E9; padding: 1rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem; color: #2E7D32; font-weight: 700; font-size: 1.05rem;">
                        <span>✓</span> Audit Log Hash Chain 100% Cryptographically Verified
                    </div>
                    <p style="margin-top: 0.5rem; font-size: 0.9rem; color: #1b5e20;">
                        ${data.message} All <strong>${data.total_records}</strong> blocks cryptographically linked to Genesis Root. No tampered, deleted, or inserted records detected.
                    </p>
                </div>
            `;
        } else {
            resultBox.innerHTML = `
                <div class="card" style="border-left: 4px solid #D32F2F; background-color: #FFEBEE; padding: 1rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem; color: #D32F2F; font-weight: 700; font-size: 1.05rem;">
                        <span>⚠</span> CRITICAL FORENSIC INTEGRITY FAILURE DETECTED
                    </div>
                    <p style="margin-top: 0.5rem; font-size: 0.9rem; color: #b71c1c;">
                        ${data.message} Broken chain at entry <strong>#${data.broken_at_id}</strong>.
                    </p>
                    <div style="margin-top: 0.5rem; font-family: monospace; font-size: 0.8rem; background: #fff; padding: 0.5rem; border-radius: 4px;">
                        Event Trigger: Forensic hash mismatch indicates unauthorized database record mutation.
                    </div>
                </div>
            `;
        }
    } catch (err) {
        resultBox.innerHTML = `
            <div class="card" style="border-left: 4px solid #D32F2F; background-color: #FFEBEE;">
                Error contacting forensic verification endpoint: ${err.message}
            </div>
        `;
    }
}

async function simulateTampering(type, targetId) {
    if (!confirm(`Are you sure you want to simulate ${type} tampering for the Viva demonstration?`)) return;
    
    try {
        const res = await fetch('/api/tamper-demo', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type, target_id: targetId })
        });
        const data = await res.json();
        alert(data.message);
        window.location.reload();
    } catch (err) {
        alert('Simulation error: ' + err.message);
    }
}
