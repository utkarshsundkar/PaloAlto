// Palo Alto & Cisco FTD Migration Agent - Frontend Logic
document.addEventListener('DOMContentLoaded', () => {
    // Tab Navigation
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const tabTitle = document.getElementById('tab-title');
    const tabSubtitle = document.getElementById('tab-subtitle');

    const tabHeadings = {
        'dashboard': { title: 'Dashboard Overview', subtitle: 'Real-time status of Cisco FTD to Palo Alto PAN-OS migration' },
        'stages': { title: 'CLI Stage Files', subtitle: 'Generated PAN-OS set command files (Stages 01–09)' },
        'policies': { title: 'Security Policy Inspector', subtitle: 'Audit, search, and fix converted security rules' },
        'push': { title: 'Live Push Agent', subtitle: 'Execute automated CLI migration and commit to firewall' },
        'settings': { title: 'Firewall Credentials', subtitle: 'Manage Palo Alto SSH credentials and target settings' }
    };

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            
            navButtons.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`pane-${targetTab}`).classList.add('active');

            if (tabHeadings[targetTab]) {
                tabTitle.textContent = tabHeadings[targetTab].title;
                tabSubtitle.textContent = tabHeadings[targetTab].subtitle;
            }

            if (targetTab === 'stages') loadStages();
            if (targetTab === 'policies') loadPolicies();
        });
    });

    // Modal Control
    const credModal = document.getElementById('credentials-modal');
    const openModal = () => { credModal.style.display = 'flex'; };
    const closeModal = () => { credModal.style.display = 'none'; };

    document.getElementById('btn-open-cred-modal')?.addEventListener('click', openModal);
    document.getElementById('btn-header-creds')?.addEventListener('click', openModal);
    document.getElementById('modal-close-btn')?.addEventListener('click', closeModal);

    // Save credentials from Modal
    document.getElementById('btn-modal-save')?.addEventListener('click', async () => {
        const host = document.getElementById('modal-ip').value;
        const username = document.getElementById('modal-username').value;
        const password = document.getElementById('modal-password').value;

        if (!host || !username) {
            alert('Please enter IP address and username.');
            return;
        }

        await saveCredentials(host, 22, username, password);
        closeModal();
    });

    // Test SSH from Modal
    document.getElementById('btn-modal-test')?.addEventListener('click', async () => {
        const host = document.getElementById('modal-ip').value;
        const username = document.getElementById('modal-username').value;
        const password = document.getElementById('modal-password').value;
        await testSshConnection(host, 22, username, password);
    });

    // Load initial data
    loadStatus();
    loadConfig();
    loadStages();
    loadPolicies();

    // Re-parse FTD Config Button
    document.getElementById('btn-parse-ftd')?.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/parse', { method: 'POST' });
            const data = await res.json();
            alert(data.message || 'Parsing started');
            setTimeout(() => {
                loadStatus();
                loadStages();
                loadPolicies();
            }, 2000);
        } catch (e) {
            alert('Failed to trigger parse: ' + e);
        }
    });

    // Fix Deny Rules Buttons
    const fixDenyAction = async () => {
        if (!confirm('Convert all rules with "Block" or "Malicious" in their name/description to action deny?')) return;
        try {
            const res = await fetch('/api/fix-deny-rules', { method: 'POST' });
            const data = await res.json();
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                alert(data.message);
                loadPolicies();
            }
        } catch (e) {
            alert('Failed to fix deny rules: ' + e);
        }
    };

    document.getElementById('btn-fix-deny')?.addEventListener('click', fixDenyAction);
    document.getElementById('btn-fix-deny-policies')?.addEventListener('click', fixDenyAction);

    // Quick Push Button
    document.getElementById('btn-quick-push')?.addEventListener('click', () => {
        document.querySelector('[data-tab="push"]').click();
    });

    // SSH Test Button in Settings Tab
    document.getElementById('btn-test-ssh')?.addEventListener('click', async () => {
        const host = document.getElementById('cfg-host').value;
        const port = document.getElementById('cfg-port').value;
        const username = document.getElementById('cfg-username').value;
        const password = document.getElementById('cfg-password').value;
        await testSshConnection(host, port, username, password);
    });

    // Config Save Form in Settings Tab
    document.getElementById('config-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const host = document.getElementById('cfg-host').value;
        const port = document.getElementById('cfg-port').value;
        const username = document.getElementById('cfg-username').value;
        const password = document.getElementById('cfg-password').value;
        await saveCredentials(host, port, username, password);
    });

    // Push Execution Trigger
    document.getElementById('btn-start-push-task')?.addEventListener('click', async () => {
        const host = document.getElementById('push-target-ip').value;
        const username = document.getElementById('push-username').value;
        const password = document.getElementById('push-password').value;

        if (!host || !username) {
            alert('Please specify Firewall IP Address and Username before pushing.');
            openModal();
            return;
        }

        // Auto-save credentials if changed
        if (password) {
            await saveCredentials(host, 22, username, password);
        }

        const checkedStages = Array.from(document.querySelectorAll('input[name="push_stage"]:checked')).map(cb => parseInt(cb.value));
        const chunkSize = parseInt(document.getElementById('chunk-size-input').value) || 50;
        const isLive = document.getElementById('push-live-mode').checked;
        const autoCommit = document.getElementById('push-auto-commit').checked;

        const payload = {
            stages: checkedStages,
            chunk_size: chunkSize,
            dry_run: !isLive,
            auto_commit: autoCommit
        };

        try {
            const res = await fetch('/api/push/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                startLogPolling();
            }
        } catch (e) {
            alert('Failed to launch push: ' + e);
        }
    });

    // Log Polling
    let pollInterval = null;
    function startLogPolling() {
        const term = document.getElementById('terminal-output');
        const badge = document.getElementById('push-status-badge');
        
        if (pollInterval) clearInterval(pollInterval);

        pollInterval = setInterval(async () => {
            try {
                const res = await fetch('/api/push/log');
                const data = await res.json();

                badge.textContent = data.status.toUpperCase();
                badge.className = `badge badge-${data.status === 'completed' ? 'success' : data.status === 'running' ? 'warning' : 'secondary'}`;
                
                term.textContent = data.log || 'Waiting for output...';
                term.scrollTop = term.scrollHeight;

                if (!data.is_running && data.status !== 'idle') {
                    clearInterval(pollInterval);
                }
            } catch (e) {
                console.error(e);
            }
        }, 1500);
    }
});

// Helper Function: Save Credentials
async function saveCredentials(host, port, username, password) {
    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, port: parseInt(port), username, password })
        });
        const data = await res.json();
        alert(data.message || 'Credentials updated successfully');
        loadConfig();
    } catch (err) {
        alert('Failed to save credentials: ' + err);
    }
}

// Helper Function: Test SSH Connection
async function testSshConnection(host, port, username, password) {
    try {
        const res = await fetch('/api/test-ssh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, port: parseInt(port), username, password })
        });
        const data = await res.json();
        if (data.success) {
            alert('✅ ' + data.message);
            const dot = document.getElementById('fw-status-dot');
            if (dot) dot.className = 'status-dot';
        } else {
            alert('❌ SSH Test Failed: ' + data.error);
        }
    } catch (e) {
        alert('Error testing SSH: ' + e);
    }
}

// API Helper Functions
async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();

        document.getElementById('stat-ftd-status').textContent = data.ftd_config_exists ? `Found (${data.ftd_size_mb} MB)` : 'Not Found';
        document.getElementById('stat-stages-count').textContent = `${data.stages_count} Stages`;
    } catch (e) {
        console.error(e);
    }
}

async function loadConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();

        if (data.host) {
            document.getElementById('stat-fw-ip').textContent = data.host;
            document.getElementById('header-ip-display').textContent = data.host;
            document.getElementById('fw-status-text').textContent = `Target: ${data.host}`;
            document.getElementById('stat-fw-user').textContent = `User: ${data.username || 'admin'} · Port ${data.port || 22}`;

            // Sync inputs across all tabs & modal
            ['cfg-host', 'push-target-ip', 'modal-ip'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = data.host;
            });

            ['cfg-username', 'push-username', 'modal-username'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = data.username || 'admin';
            });
        }
    } catch (e) {
        console.error(e);
    }
}

async function loadStages() {
    try {
        const res = await fetch('/api/stages');
        const data = await res.json();
        const stages = data.stages || [];

        const dashList = document.getElementById('dashboard-stages-list');
        const tableBody = document.querySelector('#stages-table tbody');

        if (dashList) {
            dashList.innerHTML = stages.map(s => `
                <div class="stage-item">
                    <div class="stage-info">
                        <h4>${s.filename}</h4>
                        <span>${(s.size_bytes / 1024).toFixed(1)} KB</span>
                    </div>
                    <span class="badge badge-primary">${s.commands_count} cmds</span>
                </div>
            `).join('');
        }

        if (tableBody) {
            tableBody.innerHTML = stages.map((s, idx) => `
                <tr>
                    <td><strong>Stage 0${idx + 1}</strong></td>
                    <td><code>${s.filename}</code></td>
                    <td><span class="badge badge-primary">${s.commands_count} commands</span></td>
                    <td>${(s.size_bytes / 1024).toFixed(1)} KB</td>
                    <td>
                        <button class="btn btn-sm btn-outline" onclick="previewStage('${s.filename}')">👁️ Preview</button>
                    </td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error(e);
    }
}

let allPolicies = [];
async function loadPolicies() {
    try {
        const res = await fetch('/api/policies');
        const data = await res.json();
        allPolicies = data.rules || [];

        const suspectCount = allPolicies.filter(r => r.is_block_suspect).length;
        document.getElementById('suspects-count-badge').textContent = suspectCount;
        document.getElementById('stat-policy-count').textContent = `${data.total} Rules`;
        document.getElementById('stat-suspects-desc').textContent = suspectCount > 0 ? `⚠️ ${suspectCount} block rules need action fix` : 'All block actions verified';

        renderPoliciesTable(allPolicies);

        // Attach search listeners
        document.getElementById('policy-search')?.addEventListener('input', filterPolicies);
        document.getElementById('policy-filter')?.addEventListener('change', filterPolicies);
    } catch (e) {
        console.error(e);
    }
}

function filterPolicies() {
    const q = document.getElementById('policy-search').value.toLowerCase();
    const filter = document.getElementById('policy-filter').value;

    const filtered = allPolicies.filter(r => {
        const matchesQuery = r.name.toLowerCase().includes(q) || r.source.toLowerCase().includes(q) || r.destination.toLowerCase().includes(q);
        if (!matchesQuery) return false;

        if (filter === 'allow') return r.action === 'allow';
        if (filter === 'deny') return r.action === 'deny' || r.action === 'drop';
        if (filter === 'suspects') return r.is_block_suspect;
        return true;
    });

    renderPoliciesTable(filtered);
}

function renderPoliciesTable(rules) {
    const tbody = document.querySelector('#policies-table tbody');
    if (!tbody) return;

    if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-muted text-center">No rules match the selected filter.</td></tr>';
        return;
    }

    tbody.innerHTML = rules.map(r => `
        <tr>
            <td>
                <strong>${r.name}</strong>
                ${r.is_block_suspect ? '<span class="badge badge-warning">Block Suspect</span>' : ''}
            </td>
            <td><code>${r.from || 'any'}</code></td>
            <td><code>${r.to || 'any'}</code></td>
            <td><code>${r.source || 'any'}</code></td>
            <td><code>${r.destination || 'any'}</code></td>
            <td>
                <span class="badge badge-${r.action === 'allow' ? (r.is_block_suspect ? 'warning' : 'success') : 'danger'}">
                    ${r.action.toUpperCase()}
                </span>
            </td>
        </tr>
    `).join('');
}

async function previewStage(filename) {
    try {
        const res = await fetch('/api/stages');
        const data = await res.json();
        const stage = (data.stages || []).find(s => s.filename === filename);

        if (stage) {
            document.getElementById('preview-filename').textContent = stage.filename;
            document.getElementById('preview-code-block').textContent = stage.preview.join('\n') + '\n... (truncated preview)';
            document.getElementById('stage-preview-card').style.display = 'block';
        }
    } catch (e) {
        console.error(e);
    }
}

document.getElementById('btn-close-preview')?.addEventListener('click', () => {
    document.getElementById('stage-preview-card').style.display = 'none';
});
