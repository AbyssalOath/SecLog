// ---------- Dashboard ----------
let allLogs = [];
const SEVERITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };
const DETAIL_PAGE_SIZE = 25;

let currentHost = null;
let detailPage = 0;
let expandedMessageCell = null;

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
        badge.textContent = `v${versionData.version} — Update available (v${versionData.latest_version})`;
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

    showHostSummary();
}

// ---- Host summary table (the default landing view) ----
function renderHostTable() {
    const filter = document.getElementById('host-filter-box').value.toLowerCase();
    const tbody = document.getElementById('host-rows');
    tbody.innerHTML = '';

    const byHost = new Map();
    for (const log of allLogs) {
        if (!byHost.has(log.host)) byHost.set(log.host, []);
        byHost.get(log.host).push(log);
    }

    const hosts = [...byHost.keys()]
        .filter(h => h.toLowerCase().includes(filter))
        .sort((a, b) => {
            const worstA = Math.max(...byHost.get(a).map(l => SEVERITY_RANK[l.severity] ?? 0));
            const worstB = Math.max(...byHost.get(b).map(l => SEVERITY_RANK[l.severity] ?? 0));
            if (worstB !== worstA) return worstB - worstA;
            return byHost.get(b).length - byHost.get(a).length;
        });

    for (const host of hosts) {
        const logs = byHost.get(host);
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        for (const l of logs) counts[l.severity] = (counts[l.severity] || 0) + 1;

        const row = document.createElement('tr');
        row.className = 'host-row';
        row.onclick = () => showHostDetail(host);

        const hostCell = document.createElement('td');
        const link = document.createElement('a');
        link.href = '#';
        link.className = 'host-link';
        link.textContent = host;
        link.onclick = (e) => { e.preventDefault(); showHostDetail(host); };
        hostCell.appendChild(link);

        const totalCell = document.createElement('td');
        totalCell.textContent = logs.length;
        const criticalCell = document.createElement('td');
        criticalCell.textContent = counts.Critical;
        const highCell = document.createElement('td');
        highCell.textContent = counts.High;
        const mediumCell = document.createElement('td');
        mediumCell.textContent = counts.Medium;
        const lowCell = document.createElement('td');
        lowCell.textContent = counts.Low;

        row.appendChild(hostCell);
        row.appendChild(totalCell);
        row.appendChild(criticalCell);
        row.appendChild(highCell);
        row.appendChild(mediumCell);
        row.appendChild(lowCell);
        tbody.appendChild(row);
    }
}

function showHostSummary() {
    currentHost = null;
    document.getElementById('host-summary-view').style.display = 'block';
    document.getElementById('host-detail-view').style.display = 'none';
    renderHostTable();
}

// ---- Per-host drill-down (paginated, filterable) ----
function showHostDetail(host) {
    currentHost = host;
    detailPage = 0;
    document.getElementById('host-summary-view').style.display = 'none';
    document.getElementById('host-detail-view').style.display = 'block';
    document.getElementById('host-detail-title').textContent = host;
    document.getElementById('detail-filter-box').value = '';
    renderDetailTable();
}

function changeDetailPage(delta) {
    detailPage += delta;
    renderDetailTable();
}

function makeRow(log) {
    const row = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = log.id;
    const severityCell = document.createElement('td');
    severityCell.textContent = log.severity;
    severityCell.className = 'level-' + log.severity;
    const userCell = document.createElement('td');
    userCell.textContent = log.user;

    const messageCell = document.createElement('td');
    messageCell.textContent = log.message;
    messageCell.className = 'message-cell';
    messageCell.onclick = () => {
        if (expandedMessageCell === messageCell) {
            messageCell.classList.remove('expanded');
            expandedMessageCell = null;
            return;
        }
        if (expandedMessageCell) expandedMessageCell.classList.remove('expanded');
        messageCell.classList.add('expanded');
        expandedMessageCell = messageCell;
    };

    row.appendChild(idCell);
    row.appendChild(severityCell);
    row.appendChild(userCell);
    row.appendChild(messageCell);
    return row;
}

function renderDetailTable() {
    if (!currentHost) return;

    const filter = document.getElementById('detail-filter-box').value.toLowerCase();
    const logs = allLogs.filter(l => l.host === currentHost);
    const filtered = logs.filter(l =>
        l.user.toLowerCase().includes(filter) || l.message.toLowerCase().includes(filter)
    );

    // Worst severity first.
    filtered.sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));

    const totalPages = Math.max(1, Math.ceil(filtered.length / DETAIL_PAGE_SIZE));
    if (detailPage < 0) detailPage = 0;
    if (detailPage >= totalPages) detailPage = totalPages - 1;

    const start = detailPage * DETAIL_PAGE_SIZE;
    const pageItems = filtered.slice(start, start + DETAIL_PAGE_SIZE);

    const tbody = document.getElementById('log-rows');
    tbody.innerHTML = '';
    expandedMessageCell = null;
    for (const log of pageItems) tbody.appendChild(makeRow(log));

    document.getElementById('detail-page-info').textContent =
        `Page ${detailPage + 1} of ${totalPages} (${filtered.length} total)`;
    document.getElementById('detail-prev').disabled = detailPage === 0;
    document.getElementById('detail-next').disabled = detailPage >= totalPages - 1;
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
 
    if (tab === 'security') loadUsersPanel();
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
 
let currentSettings = {};
 
async function loadGeneralSettings() {
    const response = await authFetch('/settings');
    currentSettings = await response.json();
    document.getElementById('self-signup-toggle').checked = currentSettings.self_signup_enabled;
    document.getElementById('retention-days').value = currentSettings.log_retention_days;
    document.getElementById('retention-max-rows').value = currentSettings.max_log_rows;
}
 
async function saveSettings(overrides) {
    const payload = { ...currentSettings, ...overrides };
 
    const response = await authFetch('/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
 
    if (response.ok) {
        currentSettings = payload;
    }
    document.getElementById('general-result').innerText = response.ok ? 'Saved.' : 'Failed to save: ' + response.status;
    return response.ok;
}
 
async function updateSelfSignup() {
    const enabled = document.getElementById('self-signup-toggle').checked;
    await saveSettings({ self_signup_enabled: enabled });
}
 
async function saveRetentionSettings() {
    const days = parseInt(document.getElementById('retention-days').value, 10);
    const maxRows = parseInt(document.getElementById('retention-max-rows').value, 10);
 
    if (!Number.isFinite(days) || days < 1 || !Number.isFinite(maxRows) || maxRows < 1000) {
        document.getElementById('general-result').innerText = 'Retention days must be >= 1 and max rows >= 1000.';
        return;
    }
 
    await saveSettings({ log_retention_days: days, max_log_rows: maxRows });
}
