// ---------- Dashboard ----------
let allLogs = [];

async function initDashboard() {
    const meResp = await authFetch('/me');
    if (meResp.ok) {
        const me = await meResp.json();
        document.getElementById('whoami').innerText = `${me.username} (${me.role})`;
    }

    const versionResp = await fetch('/version');
    const versionData = await versionResp.json();
    const badge = document.getElementById('version-badge');
    if (versionData.update_available) {
    	badge.textContent = `v${versionData.version} -> Update available (v${versionData.latest_version})`;
    	badge.classList.add('update-available');
    } else {
    	badge.textContent = `v${versionData.version}`;
    	badge.classList.remove('update-available');
    }

    const response = await authFetch('/logs');
    allLogs = await response.json();

    document.getElementById('stat-total').textContent = allLogs.length;
    document.getElementById('stat-errors').textContent = allLogs.filter(l => l.severity === 'High').length;
    document.getElementById('stat-warns').textContent = allLogs.filter(l => l.severity === 'Critical').length;

    renderLogTable();
}

function renderLogTable() {
    const filter = document.getElementById('filter-box').value.toLowerCase();
    const tbody = document.getElementById('log-rows');
    tbody.innerHTML = '';

    const filtered = allLogs.filter(log =>
        log.host.toLowerCase().includes(filter) ||
        log.user.toLowerCase().includes(filter) ||
        log.message.toLowerCase().includes(filter)
    );

    for (const log of filtered) {
        const row = document.createElement('tr');
        const idCell = document.createElement('td');
        idCell.textContent = log.id;
        const severityCell = document.createElement('td');
        severityCell.textContent = log.severity;
        severityCell.className = 'level-' + log.severity;
        const hostCell = document.createElement('td');
        hostCell.textContent = log.host;
        const userCell = document.createElement('td');
        userCell.textContent = log.user;
        const messageCell = document.createElement('td');
        messageCell.textContent = log.message;

        row.appendChild(idCell);
        row.appendChild(severityCell);
        row.appendChild(hostCell);
        row.appendChild(userCell);
        row.appendChild(messageCell);
        tbody.appendChild(row);
    }
}

// ---------- Users ----------
async function initUsers() {
    const response = await authFetch('/users');

    if (response.status === 403) {
        document.getElementById('users-result').innerText = 'Access denied: admin only.';
        return;
    }

    const users = await response.json();
    const tbody = document.getElementById('user-rows');
    tbody.innerHTML = '';

    for (const user of users) {
        const row = document.createElement('tr');
        const idCell = document.createElement('td');
        idCell.textContent = user.id;
        const usernameCell = document.createElement('td');
        usernameCell.textContent = user.username;
        const roleCell = document.createElement('td');
        roleCell.textContent = user.role;

        row.appendChild(idCell);
        row.appendChild(usernameCell);
        row.appendChild(roleCell);
        tbody.appendChild(row);
    }
}

// ---------- Agents ----------
async function generateEnrollmentToken() {
    const response = await authFetch('/agents/enrollment-token', { method: 'POST' });
    if (response.ok) {
        const data = await response.json();
        const origin = window.location.origin;

        document.getElementById('enrollment-result').innerHTML =
            `Token (one-time use): <code id="enrollment-token-value"></code> ` +
            `<button id="copy-enrollment-token">Copy</button><br><br>` +
            `<strong>Linux (sudo/root required):</strong><br><code>curl -sL ${origin}/install/linux.sh | bash</code><br><br>` +
            `<strong>Windows (PowerShell, as Administrator):</strong><br><code>iwr ${origin}/install/windows.ps1 | iex</code>`;

        // textContent, not innerHTML -- the token is just data, never markup.
        document.getElementById('enrollment-token-value').textContent = data.token;

        document.getElementById('copy-enrollment-token').onclick = async () => {
            try {
                await navigator.clipboard.writeText(data.token);
                const btn = document.getElementById('copy-enrollment-token');
                btn.textContent = 'Copied';
                setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
            } catch (err) {
                alert('Copy failed — select and copy the token manually.');
            }
        };
    } else {
        document.getElementById('enrollment-result').innerText = 'Failed: ' + response.status;
    }
}

let selectedAgentId = null;

async function initAgents() {
    const meResp = await authFetch('/me');
    const me = await meResp.json();

    if (me.role !== 'admin') {
        document.getElementById('agents-access-result').innerText = 'Access denied: admin only.';
        return;
    }

    document.getElementById('agents-content').style.display = 'block';
    loadAgents();
}

async function registerAgent() {
    const hostname = document.getElementById('new-hostname').value.trim();
    if (!hostname) return;

    const response = await authFetch('/agents/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname })
    });

    if (response.ok) {
        const data = await response.json();
        document.getElementById('register-result').innerText =
            `Agent registered. API key (copy now, shown only once): ${data.api_key}`;
        document.getElementById('new-hostname').value = '';
        loadAgents();
    } else {
        document.getElementById('register-result').innerText = 'Registration failed: ' + response.status;
    }
}

async function loadAgents() {
    const response = await authFetch('/agents');
    const agents = await response.json();

    const tbody = document.getElementById('agent-rows');
    tbody.innerHTML = '';

    for (const agent of agents) {
        const row = document.createElement('tr');
        const idCell = document.createElement('td');
        idCell.textContent = agent.id;
        const hostCell = document.createElement('td');
        hostCell.textContent = agent.hostname;
        const seenCell = document.createElement('td');
        seenCell.textContent = agent.last_seen ? agent.last_seen : 'Never';

        const manageCell = document.createElement('td');
        const manageBtn = document.createElement('button');
        manageBtn.textContent = 'Manage Paths';
        manageBtn.onclick = () => selectAgent(agent.id, agent.hostname);
        manageCell.appendChild(manageBtn);

        const deleteCell = document.createElement('td');
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Remove';
        deleteBtn.onclick = () => deleteAgent(agent.id);
        deleteCell.appendChild(deleteBtn);

        row.appendChild(idCell);
        row.appendChild(hostCell);
        row.appendChild(seenCell);
        row.appendChild(manageCell);
        row.appendChild(deleteCell);
        tbody.appendChild(row);
    }
}

async function deleteAgent(agentId) {
    if (!confirm('Remove this agent? Its API key will stop working immediately.')) return;

    const response = await authFetch(`/agents/${agentId}`, { method: 'DELETE' });
    if (response.ok) {
        loadAgents();
    } else {
        alert('Failed to remove agent: ' + response.status);
    }
}

function selectAgent(agentId, hostname) {
    selectedAgentId = agentId;
    document.getElementById('path-manager').style.display = 'block';
    document.getElementById('path-manager-title').innerText = `Watched Paths: ${hostname}`;
    loadPaths();
}

async function loadPaths() {
    const response = await authFetch(`/agents/${selectedAgentId}/paths`);
    const paths = await response.json();

    const tbody = document.getElementById('path-rows');
    tbody.innerHTML = '';

    for (const p of paths) {
        const row = document.createElement('tr');
        const pathCell = document.createElement('td');
        pathCell.textContent = p.path;
        const enabledCell = document.createElement('td');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = p.enabled;
        checkbox.onchange = () => togglePath(p.id, checkbox.checked);
        enabledCell.appendChild(checkbox);
        const actionCell = document.createElement('td');
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Remove';
        deleteBtn.onclick = () => deletePath(p.id);
        actionCell.appendChild(deleteBtn);

        row.appendChild(pathCell);
        row.appendChild(enabledCell);
        row.appendChild(actionCell);
        tbody.appendChild(row);
    }
}

async function addPath() {
    const path = document.getElementById('new-path').value.trim();
    if (!path) return;

    await authFetch(`/agents/${selectedAgentId}/paths`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
    });

    document.getElementById('new-path').value = '';
    loadPaths();
}

async function togglePath(pathId, enabled) {
    await authFetch(`/paths/${pathId}/enabled`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
    });
}

async function deletePath(pathId) {
    await authFetch(`/paths/${pathId}`, { method: 'DELETE' });
    loadPaths();
}

// ---------- Settings ----------
async function initSettings() {
    const meResp = await authFetch('/me');
    const me = await meResp.json();

    if (me.role !== 'admin') {
        document.getElementById('settings-access-result').innerText = 'Access denied: admin only.';
        return;
    }

    document.getElementById('settings-content').style.display = 'block';
    loadGeneralSettings();
}

function showTab(tab) {
    document.getElementById('tab-general').style.display = tab === 'general' ? 'block' : 'none';
    document.getElementById('tab-security').style.display = tab === 'security' ? 'block' : 'none';
    document.getElementById('tab-alerts').style.display = tab === 'alerts' ? 'block' : 'none';

    document.getElementById('tab-link-general').classList.toggle('active', tab === 'general');
    document.getElementById('tab-link-security').classList.toggle('active', tab === 'security');
    document.getElementById('tab-link-alerts').classList.toggle('active', tab === 'alerts');

    if (tab === 'security') {
        loadUsersPanel();
        loadMfaStatus();
    }
}

async function loadUsersPanel() {
    const response = await authFetch('/users');
    if (response.status === 403) return;
    const users = await response.json();

    const tbody = document.getElementById('user-rows');
    tbody.innerHTML = '';

    for (const user of users) {
        const row = document.createElement('tr');
        const idCell = document.createElement('td');
        idCell.textContent = user.id;
        const usernameCell = document.createElement('td');
        usernameCell.textContent = user.username;
        const roleCell = document.createElement('td');
        roleCell.textContent = user.role;
        const actionCell = document.createElement('td');
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Remove';
        delBtn.onclick = () => deleteUser(user.id);
        actionCell.appendChild(delBtn);

        row.appendChild(idCell);
        row.appendChild(usernameCell);
        row.appendChild(roleCell);
        row.appendChild(actionCell);
        tbody.appendChild(row);
    }
}

async function createUser() {
    const username = document.getElementById('new-user-username').value.trim();
    const role = document.getElementById('new-user-role').value;

    if (!username) return;

    const response = await authFetch('/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, role })
    });

    const resultEl = document.getElementById('create-user-result');

    if (response.ok) {
        const data = await response.json();

        // Keep the temporary password only in this local variable.
        // Do NOT put it in localStorage, sessionStorage, or window.
        const temporaryPassword = data.temporary_password;

        resultEl.innerHTML =
            `<strong>User created.</strong><br>` +
            `Temporary password: ` +
            `<code id="temporary-password"></code> ` +
            `<button id="copy-temporary-password">Copy</button><br>` +
            `<small>This password will be shown once. The user must change it on first login.</small>`;

        // textContent avoids interpreting the password as HTML.
        const passwordElement =
            document.getElementById('temporary-password');

        passwordElement.textContent = temporaryPassword;

        const copyButton =
            document.getElementById('copy-temporary-password');

        copyButton.onclick = async () => {
            try {
                await navigator.clipboard.writeText(temporaryPassword);

                // Immediately remove the password from the page.
                passwordElement.textContent = '[copied — no longer displayed]';

                // Disable the button so it can't be copied again.
                copyButton.disabled = true;
                copyButton.textContent = 'Copied';

                // Remove the plaintext from this closure shortly after use.
                // JavaScript cannot guarantee immediate memory erasure,
                // but this removes our references to it.
                setTimeout(() => {
                    passwordElement.remove();
                }, 1000);

            } catch (err) {
                passwordElement.textContent =
                    '[copy failed — password still visible]';
            }
        };

        document.getElementById('new-user-username').value = '';

        loadUsersPanel();

    } else if (response.status === 409) {
        resultEl.innerText = 'Username already taken.';

    } else {
        resultEl.innerText = 'Failed: ' + response.status;
    }
}

async function deleteUser(userId) {
    const response = await authFetch(`/admin/users/${userId}`, { method: 'DELETE' });
    if (response.ok) {
        loadUsersPanel();
    } else if (response.status === 400) {
        alert("You can't remove your own account.");
    } else {
        alert('Failed to remove user: ' + response.status);
    }
}

// ---------- Forced password change ----------
function initForceChangePassword() {
    document.getElementById('content').innerHTML = `
        <div class="auth-wrap">
            <div class="auth-card">
                <h1>SECLOG</h1>
                <div class="tagline">Password Change Required</div>
                <input id="cp-current" type="password" placeholder="Current Password">
                <input id="cp-new" type="password" placeholder="New Password (15+ chars)">
                <input id="cp-confirm" type="password" placeholder="Confirm New Password">
                <button onclick="submitPasswordChange()">Update Password</button>
                <div id="cp-result" style="color:var(--blood-bright); margin-top:0.75rem; font-size:0.8rem;"></div>
            </div>
        </div>
    `;
}

async function submitPasswordChange() {
    const current = document.getElementById('cp-current').value;
    const next = document.getElementById('cp-new').value;
    const confirmVal = document.getElementById('cp-confirm').value;

    if (next.length < 15) {
        document.getElementById('cp-result').innerText = 'New password must be at least 15 characters.';
        return;
    }
    if (next !== confirmVal) {
        document.getElementById('cp-result').innerText = 'Passwords do not match.';
        return;
    }

    // Deliberately NOT using authFetch here: its blanket 401-handling would
    // log the user out on a wrong "current password" guess, when what we
    // actually want is to show an error and let them retry.
    const response = await fetch('/change-password', {
    	method: 'POST',
	credentials: 'include',
    	headers: {
            'Content-Type': 'application/json'
    	},
    	body: JSON.stringify({
            current_password: current,
            new_password: next
    	})
    });

    if (response.ok) {
	sessionStorage.removeItem('must_change_password');
        renderSidebar();
        navigateTo('/dashboard');
    } else if (response.status === 401) {
        document.getElementById('cp-result').innerText = 'Current password incorrect.';
    } else {
        document.getElementById('cp-result').innerText = 'Failed: ' + response.status;
    }
}

async function loadGeneralSettings() {
    const response = await authFetch('/settings');
    const settings = await response.json();
    document.getElementById('self-signup-toggle').checked = settings.self_signup_enabled;
}

async function updateSelfSignup() {
    const enabled = document.getElementById('self-signup-toggle').checked;

    const response = await authFetch('/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ self_signup_enabled: enabled })
    });

    document.getElementById('general-result').innerText = response.ok ? 'Saved.' : 'Failed to save: ' + response.status;
}

// ---------- MFA ----------
// QR rendering is loaded lazily and only client-side -- the server never
// generates an image, just the otpauth:// URL and the base32 secret; this
// library turns the URL into a scannable code in the browser.
let mfaQrLibLoaded = false;
let mfaCurrentSecretBase32 = '';

function loadMfaQrLib() {
    return new Promise((resolve, reject) => {
        if (mfaQrLibLoaded || window.QRCode) {
            mfaQrLibLoaded = true;
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
        script.onload = () => { mfaQrLibLoaded = true; resolve(); };
        script.onerror = () => reject(new Error('Failed to load QR code library'));
        document.head.appendChild(script);
    });
}

function setMfaResult(text, ok) {
    const el = document.getElementById('mfa-result');
    el.style.color = ok ? '#4caf50' : 'var(--blood-bright)';
    el.innerText = text;
}

async function loadMfaStatus() {
    const response = await authFetch('/mfa/status');
    if (!response.ok) return;
    const data = await response.json();

    document.getElementById('mfa-status-off').style.display = data.mfa_enabled ? 'none' : 'block';
    document.getElementById('mfa-status-on').style.display = data.mfa_enabled ? 'block' : 'none';
    document.getElementById('mfa-setup-flow').style.display = 'none';
    document.getElementById('mfa-result').innerText = '';
}

async function startMfaSetup() {
    const response = await authFetch('/mfa/setup', { method: 'POST' });

    if (!response.ok) {
        setMfaResult('Failed to start MFA setup: ' + response.status, false);
        return;
    }

    const data = await response.json();
    mfaCurrentSecretBase32 = data.secret_base32;

    document.getElementById('mfa-manual-secret').textContent = data.secret_base32;
    document.getElementById('mfa-verify-code').value = '';
    document.getElementById('mfa-result').innerText = '';
    document.getElementById('mfa-setup-flow').style.display = 'block';

    try {
        await loadMfaQrLib();
        const qrParent = document.getElementById('mfa-qr-container');
        qrParent.innerHTML = ''; // clear any previous QR before redrawing
        new QRCode(qrParent, {
            text: data.otpauth_url,
            width: 200,
            height: 200,
        });
    } catch (e) {
        setMfaResult('QR rendering unavailable -- use the manual key below instead.', false);
    }
}

async function confirmMfaSetup() {
    const code = document.getElementById('mfa-verify-code').value.trim();

    if (!/^\d{6}$/.test(code)) {
        setMfaResult('Enter the 6-digit code from your authenticator app.', false);
        return;
    }

    const response = await authFetch('/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
    });

    if (response.ok) {
        setMfaResult('MFA enabled.', true);
        loadMfaStatus();
    } else if (response.status === 401) {
        setMfaResult('Incorrect code. Try again.', false);
    } else {
        setMfaResult('Failed: ' + response.status, false);
    }
}

function cancelMfaSetup() {
    document.getElementById('mfa-setup-flow').style.display = 'none';
    document.getElementById('mfa-result').innerText = '';
}

async function disableMfa() {
    const password = document.getElementById('mfa-disable-password').value;

    if (!password) {
        setMfaResult('Enter your current password to disable MFA.', false);
        return;
    }

    const response = await authFetch('/mfa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    });

    document.getElementById('mfa-disable-password').value = '';

    if (response.ok) {
        setMfaResult('MFA disabled.', true);
        loadMfaStatus();
    } else if (response.status === 401) {
        setMfaResult('Incorrect password.', false);
    } else {
        setMfaResult('Failed: ' + response.status, false);
    }
}

async function copyMfaSecret() {
    try {
        await navigator.clipboard.writeText(mfaCurrentSecretBase32);
        const btn = document.getElementById('mfa-copy-secret');
        btn.textContent = 'Copied';
        btn.disabled = true;
        setTimeout(() => { btn.textContent = 'Copy'; btn.disabled = false; }, 1500);
    } catch (e) {
        // Clipboard API unavailable -- the key is still visible to select and copy manually.
    }
}
