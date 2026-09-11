// ---------- Dashboard ----------
// /logs and /logs/summary are admin-only (CJIS AU-9). Both are also
// genuinely paginated/aggregated server-side, not "fetch everything and
// slice it in the browser" -- see the comments on list_logs/logs_summary
// in main.rs for why (600k+ rows once crashed a browser tab this way).
let hostSummary = [];
const DETAIL_PAGE_SIZE = 25;

let currentHost = null;
let detailPage = 0;
let detailTotal = 0;
let currentPageLogs = [];
let expandedMessageCell = null;

async function initDashboard() {
    const meResp = await authFetch('/me');
    if (!meResp.ok) return;
    const me = await meResp.json();
    document.getElementById('whoami').innerText = `${me.username} (${me.role})`;

    if (me.role !== 'admin' && me.role !== 'auditor') {
        document.getElementById('dashboard-access-result').innerText = 'Access denied: admin or auditor only.';
        return;
    }
    document.getElementById('dashboard-content').style.display = 'block';

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

    await loadHostSummary();
}

// ---- Host summary table (the default landing view) ----
async function loadHostSummary() {
    const response = await authFetch('/logs/summary');
    if (!response.ok) return;
    hostSummary = await response.json();

    let total = 0, high = 0, critical = 0;
    for (const h of hostSummary) {
        total += h.total;
        high += h.high;
        critical += h.critical;
    }
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-errors').textContent = high;
    document.getElementById('stat-warns').textContent = critical;

    showHostSummary();
}

function renderHostTable() {
    const filter = document.getElementById('host-filter-box').value.toLowerCase();
    const tbody = document.getElementById('host-rows');
    tbody.innerHTML = '';

    // Already ordered by the server: most critical, then most high, etc.
    const hosts = hostSummary.filter(h => h.host.toLowerCase().includes(filter));

    for (const h of hosts) {
        const row = document.createElement('tr');
        row.className = 'host-row';
        row.onclick = () => showHostDetail(h.host);

        const hostCell = document.createElement('td');
        const link = document.createElement('a');
        link.href = '#';
        link.className = 'host-link';
        link.textContent = h.host;
        link.onclick = (e) => { e.preventDefault(); showHostDetail(h.host); };
        hostCell.appendChild(link);

        const totalCell = document.createElement('td');
        totalCell.textContent = h.total;
        const criticalCell = document.createElement('td');
        criticalCell.textContent = h.critical;
        const highCell = document.createElement('td');
        highCell.textContent = h.high;
        const mediumCell = document.createElement('td');
        mediumCell.textContent = h.medium;
        const lowCell = document.createElement('td');
        lowCell.textContent = h.low;

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
    document.getElementById('detail-severity-filter').value = '';
    document.getElementById('detail-review-filter').value = '';
    loadDetailPage();
}

async function changeDetailPage(delta) {
    detailPage += delta;
    await loadDetailPage();
}

// Fetches one page of this host's logs from the server -- already
// sorted most-severe-first by get_logs_for_host. The text/severity
// filters below only ever act on this one page's worth of rows, same
// documented limitation as before (see the panel-desc in
// dashboard.html): a real cross-page search would need the server to
// support it, which /logs doesn't yet.
async function loadDetailPage() {
    if (!currentHost) return;

    const offset = detailPage * DETAIL_PAGE_SIZE;
    const url = `/logs?host=${encodeURIComponent(currentHost)}&limit=${DETAIL_PAGE_SIZE}&offset=${offset}`;
    const response = await authFetch(url);
    if (!response.ok) return;

    const data = await response.json();
    currentPageLogs = data.logs;
    detailTotal = data.total;
    renderDetailTable();
}

const REVIEW_STATUS_LABELS = { open: 'Open', reviewed: 'Reviewed', false_positive: 'False Positive' };

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
    row.appendChild(makeReviewCell(log));
    return row;
}

// CJIS AU-6: a status pill that expands into an inline review form
// (status + note + Save) on click, instead of a separate page/modal --
// matches the message cell's own click-to-expand pattern above.
function makeReviewCell(log) {
    const cell = document.createElement('td');

    const pill = document.createElement('span');
    pill.className = 'status-pill status-review-' + log.review_status.replace('_', '-');
    pill.textContent = REVIEW_STATUS_LABELS[log.review_status] || log.review_status;
    cell.appendChild(pill);

    const panel = document.createElement('div');
    panel.className = 'review-panel';
    panel.hidden = true;

    const statusSelect = document.createElement('select');
    for (const [value, label] of Object.entries(REVIEW_STATUS_LABELS)) {
        const opt = document.createElement('option');
        opt.value = value;
        opt.textContent = label;
        if (value === log.review_status) opt.selected = true;
        statusSelect.appendChild(opt);
    }

    const noteBox = document.createElement('textarea');
    noteBox.placeholder = 'Investigation note (optional)';
    noteBox.value = log.review_note || '';

    if (log.reviewed_by_username) {
        const meta = document.createElement('div');
        meta.className = 'hint';
        meta.style.margin = '0';
        meta.textContent = `Last reviewed by ${log.reviewed_by_username} at ${new Date(log.reviewed_at).toLocaleString()}`;
        panel.appendChild(meta);
    }

    const saveBtn = document.createElement('button');
    saveBtn.textContent = 'Save';
    saveBtn.onclick = async () => {
        const response = await authFetch(`/logs/${log.id}/review`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: statusSelect.value, note: noteBox.value || null })
        });
        if (response.ok) {
            log.review_status = statusSelect.value;
            log.review_note = noteBox.value;
            pill.className = 'status-pill status-review-' + statusSelect.value.replace('_', '-');
            pill.textContent = REVIEW_STATUS_LABELS[statusSelect.value];
            panel.hidden = true;
        } else {
            saveBtn.textContent = 'Failed: ' + response.status;
        }
    };

    panel.appendChild(statusSelect);
    panel.appendChild(noteBox);
    panel.appendChild(saveBtn);
    cell.appendChild(panel);

    pill.onclick = () => { panel.hidden = !panel.hidden; };

    return cell;
}

function renderDetailTable() {
    if (!currentHost) return;

    const filter = document.getElementById('detail-filter-box').value.toLowerCase();
    const severityFilter = document.getElementById('detail-severity-filter').value;
    const reviewFilter = document.getElementById('detail-review-filter').value;

    // Filters only apply within the already-fetched current page -- see
    // the comment on loadDetailPage.
    const filtered = currentPageLogs.filter(l =>
        (l.user.toLowerCase().includes(filter) || l.message.toLowerCase().includes(filter)) &&
        (severityFilter === '' || l.severity === severityFilter) &&
        (reviewFilter === '' || l.review_status === reviewFilter)
    );

    const tbody = document.getElementById('log-rows');
    tbody.innerHTML = '';
    expandedMessageCell = null;
    for (const log of filtered) tbody.appendChild(makeRow(log));

    const totalPages = Math.max(1, Math.ceil(detailTotal / DETAIL_PAGE_SIZE));
    document.getElementById('detail-page-info').textContent =
        `Page ${detailPage + 1} of ${totalPages} (${detailTotal} total)`;
    document.getElementById('detail-prev').disabled = detailPage <= 0;
    document.getElementById('detail-next').disabled = detailPage + 1 >= totalPages;
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

// ---------- Directory (LDAP/Active Directory) ----------
async function initDirectory() {
    const meResp = await authFetch('/me');
    const me = await meResp.json();

    if (me.role !== 'admin') {
        document.getElementById('directory-access-result').innerText = 'Access denied: admin only.';
        return;
    }

    document.getElementById('directory-content').style.display = 'block';
    loadDirectoryConfig();
    loadDirectoryHosts();
    loadDeploymentTokens();
}

function formatDirectoryTimestamp(value) {
    if (!value) return 'Never';
    return new Date(value).toLocaleString();
}

async function loadDirectoryConfig() {
    const response = await authFetch('/directory/config');
    if (!response.ok) {
        document.getElementById('directory-config-result').innerText = 'Failed to load config: ' + response.status;
        return;
    }
    const cfg = await response.json();

    document.getElementById('ldap-server-uri').value = cfg.server_uri;
    document.getElementById('ldap-bind-dn').value = cfg.bind_dn;
    document.getElementById('ldap-base-dn').value = cfg.base_dn;
    document.getElementById('ldap-computer-filter').value = cfg.computer_filter;
    document.getElementById('ldap-sync-interval').value = cfg.sync_interval_minutes;
    document.getElementById('ldap-enabled-toggle').checked = cfg.enabled;

    document.getElementById('ldap-user-base-dn').value = cfg.user_base_dn;
    document.getElementById('ldap-user-filter').value = cfg.user_filter_template;
    document.getElementById('ldap-admin-group-dn').value = cfg.admin_group_dn || '';
    document.getElementById('ldap-login-enabled-toggle').checked = cfg.login_enabled;

    document.getElementById('ldap-password-status').innerText =
        cfg.password_configured ? '(bind password is set -- leave blank to keep it)' : '(no bind password saved yet)';

    document.getElementById('directory-master-key-warning').style.display = cfg.master_key_configured ? 'none' : 'block';

    const statusEl = document.getElementById('directory-sync-status');
    if (!cfg.last_sync_at) {
        statusEl.innerText = 'Never synced yet.';
    } else {
        const outcome = cfg.last_sync_status === 'ok'
            ? `ok, ${cfg.last_sync_count} host(s) found`
            : `failed`;
        statusEl.innerText = `Last synced ${formatDirectoryTimestamp(cfg.last_sync_at)} -- ${outcome}.`;
    }
}

function readDirectoryConfigForm() {
    const password = document.getElementById('ldap-bind-password').value;
    return {
        enabled: document.getElementById('ldap-enabled-toggle').checked,
        server_uri: document.getElementById('ldap-server-uri').value.trim(),
        bind_dn: document.getElementById('ldap-bind-dn').value.trim(),
        bind_password: password ? password : null,
        base_dn: document.getElementById('ldap-base-dn').value.trim(),
        computer_filter: document.getElementById('ldap-computer-filter').value.trim() || '(objectClass=computer)',
        sync_interval_minutes: parseInt(document.getElementById('ldap-sync-interval').value, 10) || 60,
        login_enabled: document.getElementById('ldap-login-enabled-toggle').checked,
        user_base_dn: document.getElementById('ldap-user-base-dn').value.trim(),
        user_filter_template: document.getElementById('ldap-user-filter').value.trim() || '(&(objectClass=user)(sAMAccountName={username}))',
        admin_group_dn: document.getElementById('ldap-admin-group-dn').value.trim() || null,
    };
}

async function saveDirectoryConfig() {
    const response = await authFetch('/directory/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(readDirectoryConfigForm())
    });

    const resultEl = document.getElementById('directory-config-result');
    if (response.ok) {
        resultEl.innerText = 'Saved.';
        document.getElementById('ldap-bind-password').value = '';
        loadDirectoryConfig();
    } else if (response.status === 503) {
        resultEl.innerText = 'Cannot save a bind password: SECLOG_MASTER_KEY is not set on the server.';
    } else {
        resultEl.innerText = 'Save failed: ' + response.status;
    }
}

async function testDirectoryConnection() {
    const resultEl = document.getElementById('directory-config-result');
    resultEl.innerText = 'Testing...';

    const response = await authFetch('/directory/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(readDirectoryConfigForm())
    });

    if (response.ok) {
        resultEl.innerText = 'Connection OK -- bind succeeded.';
    } else if (response.status === 503) {
        resultEl.innerText = 'Cannot test: SECLOG_MASTER_KEY is not set on the server.';
    } else {
        resultEl.innerText = 'Connection test failed: ' + response.status;
    }
}

async function syncDirectoryNow() {
    const resultEl = document.getElementById('directory-config-result');
    resultEl.innerText = 'Syncing...';

    const response = await authFetch('/directory/sync', { method: 'POST' });

    if (response.ok) {
        const data = await response.json();
        resultEl.innerText = `Sync complete -- ${data.hosts_found} host(s) found.`;
        loadDirectoryConfig();
        loadDirectoryHosts();
    } else if (response.status === 503) {
        resultEl.innerText = 'Cannot sync: SECLOG_MASTER_KEY is not set on the server.';
    } else {
        resultEl.innerText = 'Sync failed: ' + response.status;
    }
}

async function loadDirectoryHosts() {
    const response = await authFetch('/directory/hosts');
    if (!response.ok) return;
    const hosts = await response.json();

    const tbody = document.getElementById('directory-host-rows');
    tbody.innerHTML = '';

    // Feeds the Deployment Packages label field -- suggestions only,
    // typing anything else is fine since the label isn't enforced.
    const ouList = document.getElementById('deploy-ou-options');
    ouList.innerHTML = '';
    const seenOus = new Set();
    for (const host of hosts) {
        if (host.organizational_unit && !seenOus.has(host.organizational_unit)) {
            seenOus.add(host.organizational_unit);
            const opt = document.createElement('option');
            opt.value = host.organizational_unit;
            ouList.appendChild(opt);
        }
    }

    for (const host of hosts) {
        const row = document.createElement('tr');

        const hostCell = document.createElement('td');
        hostCell.textContent = host.hostname;

        const ouCell = document.createElement('td');
        ouCell.textContent = host.organizational_unit || '—';

        const osCell = document.createElement('td');
        osCell.textContent = host.operating_system || '—';

        const seenCell = document.createElement('td');
        seenCell.textContent = formatDirectoryTimestamp(host.last_seen_in_ad);

        const statusCell = document.createElement('td');
        const pill = document.createElement('span');
        if (host.stale) {
            pill.className = 'status-pill status-stale';
            pill.textContent = 'Stale';
        } else if (host.likely_enrolled) {
            pill.className = 'status-pill status-enrolled';
            pill.textContent = 'Likely enrolled';
        } else {
            pill.className = 'status-pill status-not-enrolled';
            pill.textContent = 'Not enrolled';
        }
        statusCell.appendChild(pill);

        const actionCell = document.createElement('td');
        if (!host.likely_enrolled) {
            const tokenBtn = document.createElement('button');
            tokenBtn.textContent = 'Generate Token';
            tokenBtn.onclick = () => generateTokenForHost(host.hostname, host.operating_system);
            actionCell.appendChild(tokenBtn);
        }

        row.appendChild(hostCell);
        row.appendChild(ouCell);
        row.appendChild(osCell);
        row.appendChild(seenCell);
        row.appendChild(statusCell);
        row.appendChild(actionCell);
        tbody.appendChild(row);
    }
}

// Reuses the same one-time enrollment token endpoint the Agents page
// uses -- Directory doesn't mint its own credentials, it just surfaces
// the existing flow where discovery makes it obvious it's needed.
async function generateTokenForHost(hostname, operatingSystem) {
    const response = await authFetch('/agents/enrollment-token', { method: 'POST' });
    const box = document.getElementById('directory-token-result');

    if (!response.ok) {
        box.style.display = 'block';
        box.innerHTML = '';
        box.textContent = 'Failed to generate token: ' + response.status;
        return;
    }

    const data = await response.json();
    const origin = window.location.origin;
    const isWindows = (operatingSystem || '').toLowerCase().includes('windows');

    const linuxCmd = `curl -sL ${origin}/install/linux.sh | bash`;
    const windowsCmd = `iwr ${origin}/install/windows.ps1 | iex`;
    const primary = isWindows
        ? `<strong>Windows (PowerShell, as Administrator):</strong><br><code>${windowsCmd}</code>`
        : `<strong>Linux (sudo/root required):</strong><br><code>${linuxCmd}</code>`;
    const secondary = isWindows
        ? `<strong>Linux (sudo/root required):</strong><br><code>${linuxCmd}</code>`
        : `<strong>Windows (PowerShell, as Administrator):</strong><br><code>${windowsCmd}</code>`;

    box.style.display = 'block';
    box.innerHTML = ''; // clear before rebuilding

    // hostname comes from AD via the directory sync -- treat it as data,
    // never markup, same as the enrollment token itself.
    const heading = document.createElement('h2');
    heading.textContent = `Enrollment token for ${hostname}`;
    box.appendChild(heading);

    const tokenLine = document.createElement('div');
    tokenLine.append('Token (one-time use): ');
    const tokenCode = document.createElement('code');
    tokenCode.textContent = data.token;
    tokenLine.appendChild(tokenCode);
    box.appendChild(tokenLine);

    const commands = document.createElement('div');
    commands.style.marginTop = '0.75rem';
    commands.innerHTML = `${primary}<br><br>${secondary}`; // only static text + origin, no AD-sourced data
    box.appendChild(commands);
}

// ---------- Deployment Packages (GPO / Intune) ----------

async function generateDeploymentPackage() {
    const resultEl = document.getElementById('deploy-package-result');
    const maxUses = parseInt(document.getElementById('deploy-max-uses').value, 10);
    const expiresDays = parseInt(document.getElementById('deploy-expires-days').value, 10);
    const label = document.getElementById('deploy-label').value.trim();

    if (!maxUses || maxUses < 1 || !expiresDays || expiresDays < 1) {
        resultEl.style.display = 'block';
        resultEl.textContent = 'Max uses and expiry must be at least 1.';
        return;
    }

    const response = await authFetch('/directory/deployment-package', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label || null, max_uses: maxUses, expires_days: expiresDays })
    });

    resultEl.style.display = 'block';
    resultEl.innerHTML = '';

    if (!response.ok) {
        resultEl.textContent = 'Failed to generate package: ' + response.status;
        return;
    }

    const data = await response.json();

    const heading = document.createElement('h2');
    heading.textContent = 'Deployment package ready';
    resultEl.appendChild(heading);

    const warning = document.createElement('div');
    warning.className = 'hint';
    warning.textContent = 'The enrollment token is embedded in this script -- shown once, same as any other credential. Save the .ps1 file now.';
    resultEl.appendChild(warning);

    const textarea = document.createElement('textarea');
    textarea.readOnly = true;
    textarea.value = data.script;
    textarea.style.width = '100%';
    textarea.style.height = '220px';
    textarea.style.marginTop = '0.5rem';
    textarea.style.fontFamily = 'monospace';
    resultEl.appendChild(textarea);

    const actions = document.createElement('div');
    actions.style.marginTop = '0.5rem';
    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy Script';
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(data.script);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy Script'; }, 1500);
    };
    const downloadBtn = document.createElement('button');
    downloadBtn.textContent = 'Download .ps1';
    downloadBtn.style.marginLeft = '0.5rem';
    downloadBtn.onclick = () => downloadTextFile(data.script, 'seclog-install.ps1');
    actions.appendChild(copyBtn);
    actions.appendChild(downloadBtn);
    resultEl.appendChild(actions);

    const instructions = document.createElement('div');
    instructions.style.marginTop = '1rem';
    instructions.innerHTML = `
        <strong>Group Policy:</strong>
        <p class="hint" style="margin:0.25rem 0 0.75rem;">${data.gpo_instructions}</p>
        <strong>Intune:</strong>
        <p class="hint" style="margin:0.25rem 0;">${data.intune_instructions}</p>
    `; // static text from our own server response, not user/AD-sourced
    resultEl.appendChild(instructions);

    document.getElementById('deploy-label').value = '';
    loadDeploymentTokens();
}

function downloadTextFile(text, filename) {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function loadDeploymentTokens() {
    const response = await authFetch('/directory/deployment-tokens');
    if (!response.ok) return;
    const tokens = await response.json();

    const tbody = document.getElementById('deploy-token-rows');
    tbody.innerHTML = '';

    const now = new Date();
    for (const t of tokens) {
        const row = document.createElement('tr');

        const labelCell = document.createElement('td');
        labelCell.textContent = t.label || '—';

        const usesCell = document.createElement('td');
        usesCell.textContent = `${t.use_count} / ${t.max_uses}`;

        const createdCell = document.createElement('td');
        createdCell.textContent = formatDirectoryTimestamp(t.created_at);

        const expiresCell = document.createElement('td');
        const expired = t.expires_at && new Date(t.expires_at) <= now;
        expiresCell.textContent = t.expires_at
            ? formatDirectoryTimestamp(t.expires_at) + (expired ? ' (expired)' : '')
            : 'Never';

        const actionCell = document.createElement('td');
        if (!expired) {
            const revokeBtn = document.createElement('button');
            revokeBtn.textContent = 'Revoke';
            revokeBtn.style.background = 'transparent';
            revokeBtn.style.borderColor = 'var(--border)';
            revokeBtn.style.color = 'var(--text-dim)';
            revokeBtn.onclick = () => revokeDeploymentToken(t.id);
            actionCell.appendChild(revokeBtn);
        }

        row.appendChild(labelCell);
        row.appendChild(usesCell);
        row.appendChild(createdCell);
        row.appendChild(expiresCell);
        row.appendChild(actionCell);
        tbody.appendChild(row);
    }
}

async function revokeDeploymentToken(id) {
    if (!confirm('Revoke this deployment package? Any machine that hasn\'t run it yet will no longer be able to enroll with it.')) return;

    const response = await authFetch(`/directory/deployment-tokens/${id}`, { method: 'DELETE' });
    if (response.ok) {
        loadDeploymentTokens();
    } else {
        alert('Failed to revoke: ' + response.status);
    }
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
    loadArchiveConfig();
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

    if (tab === 'alerts') {
    	loadNotificationChannels();
    	renderChannelFields();
    	loadCorrelationLabels();
    	loadCorrelationRules();
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
        const authCell = document.createElement('td');
        authCell.textContent = user.auth_source === 'ldap' ? 'Directory' : 'Local';
        const actionCell = document.createElement('td');
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Remove';
        delBtn.onclick = () => deleteUser(user.id);
        actionCell.appendChild(delBtn);

        row.appendChild(idCell);
        row.appendChild(usernameCell);
        row.appendChild(roleCell);
        row.appendChild(authCell);
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
    document.getElementById('stale-agent-minutes').value = currentSettings.stale_agent_minutes;

    const bytes = currentSettings.logs_table_size_bytes || 0;
    const gb = bytes / 1_073_741_824;
    document.getElementById('log-table-size').innerText =
        gb >= 0.1 ? `Current size on disk: ≈${gb.toFixed(2)} GB` : `Current size on disk: ${(bytes / 1_048_576).toFixed(1)} MB`;
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

async function saveStaleAgentMinutes() {
    const minutes = parseInt(document.getElementById('stale-agent-minutes').value, 10);

    if (!Number.isFinite(minutes) || minutes < 5) {
        document.getElementById('general-result').innerText = 'Must be at least 5 minutes.';
        return;
    }

    await saveSettings({ stale_agent_minutes: minutes });
}

// ---------- Archival Storage ----------

function renderArchiveFields() {
    const backend = document.getElementById('archive-backend').value;
    document.getElementById('archive-fields-s3').style.display = backend === 's3' ? 'block' : 'none';
    document.getElementById('archive-fields-sftp').style.display = backend === 'sftp' ? 'block' : 'none';
}

async function loadArchiveConfig() {
    const response = await authFetch('/archive/config');
    if (!response.ok) return;
    const cfg = await response.json();

    document.getElementById('archive-backend').value = cfg.backend;
    document.getElementById('archive-s3-endpoint').value = cfg.s3_endpoint;
    document.getElementById('archive-s3-bucket').value = cfg.s3_bucket;
    document.getElementById('archive-s3-region').value = cfg.s3_region;
    document.getElementById('archive-s3-access-key').value = cfg.s3_access_key;
    document.getElementById('archive-s3-path-style').checked = cfg.s3_path_style;
    document.getElementById('archive-s3-secret-status').innerText =
        cfg.s3_secret_key_configured ? '(secret key is set -- leave blank to keep it)' : '(no secret key saved yet)';

    document.getElementById('archive-sftp-host').value = cfg.sftp_host;
    document.getElementById('archive-sftp-port').value = cfg.sftp_port;
    document.getElementById('archive-sftp-username').value = cfg.sftp_username;
    document.getElementById('archive-sftp-remote-path').value = cfg.sftp_remote_path;
    document.getElementById('archive-sftp-password-status').innerText =
        cfg.sftp_password_configured ? '(password is set -- leave blank to keep it)' : '(no password saved)';
    document.getElementById('archive-sftp-key-status').innerText =
        cfg.sftp_private_key_configured ? 'Private key is set -- leave blank to keep it.' : 'No private key saved.';

    document.getElementById('archive-master-key-warning').style.display = cfg.master_key_configured ? 'none' : 'block';

    const statusEl = document.getElementById('archive-status');
    if (!cfg.last_archive_at) {
        statusEl.innerText = cfg.backend === 'none' ? '' : 'No archive run yet.';
    } else {
        const outcome = cfg.last_archive_status === 'ok' ? `ok, ${cfg.last_archive_count} row(s) archived` : 'failed';
        statusEl.innerText = `Last archive run ${formatDirectoryTimestamp(cfg.last_archive_at)} -- ${outcome}.`;
    }

    renderArchiveFields();
}

async function saveArchiveConfig() {
    const payload = {
        backend: document.getElementById('archive-backend').value,
        enabled: document.getElementById('archive-backend').value !== 'none',
        s3_endpoint: document.getElementById('archive-s3-endpoint').value.trim(),
        s3_bucket: document.getElementById('archive-s3-bucket').value.trim(),
        s3_region: document.getElementById('archive-s3-region').value.trim() || 'us-east-1',
        s3_access_key: document.getElementById('archive-s3-access-key').value.trim(),
        s3_secret_key: document.getElementById('archive-s3-secret-key').value || null,
        s3_path_style: document.getElementById('archive-s3-path-style').checked,
        sftp_host: document.getElementById('archive-sftp-host').value.trim(),
        sftp_port: parseInt(document.getElementById('archive-sftp-port').value, 10) || 22,
        sftp_username: document.getElementById('archive-sftp-username').value.trim(),
        sftp_password: document.getElementById('archive-sftp-password').value || null,
        sftp_private_key: document.getElementById('archive-sftp-private-key').value || null,
        sftp_remote_path: document.getElementById('archive-sftp-remote-path').value.trim(),
    };

    const response = await authFetch('/archive/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const resultEl = document.getElementById('archive-config-result');
    if (response.ok) {
        resultEl.innerText = 'Saved.';
        document.getElementById('archive-s3-secret-key').value = '';
        document.getElementById('archive-sftp-password').value = '';
        document.getElementById('archive-sftp-private-key').value = '';
        loadArchiveConfig();
    } else if (response.status === 503) {
        resultEl.innerText = 'Cannot save a secret: SECLOG_MASTER_KEY is not set on the server.';
    } else {
        resultEl.innerText = 'Save failed: ' + response.status;
    }
}

async function testArchiveConnection() {
    const resultEl = document.getElementById('archive-config-result');
    resultEl.innerText = 'Testing...';

    const response = await authFetch('/archive/test', { method: 'POST' });

    if (response.ok) {
        resultEl.innerText = 'Connection OK -- a small test file was uploaded.';
    } else if (response.status === 400) {
        resultEl.innerText = 'Pick and save a backend first.';
    } else {
        resultEl.innerText = 'Connection test failed: ' + response.status;
    }
}

// ---------- Audit Log ----------
const AUDIT_LOG_PAGE_SIZE = 25;
let auditLogPage = 0;
let auditLogTotal = 0;

async function initAuditLogPage() {
    const meResp = await authFetch('/me');
    if (!meResp.ok) return;
    const me = await meResp.json();

    if (me.role !== 'admin' && me.role !== 'auditor') {
        document.getElementById('audit-log-access-result').innerText = 'Access denied: admin or auditor only.';
        return;
    }
    document.getElementById('audit-log-content').style.display = 'block';

    auditLogPage = 0;
    loadAuditLog();
    loadLogCheckpoints();
}

async function verifyAuditChain() {
    const resultEl = document.getElementById('audit-verify-result');
    resultEl.innerText = 'Verifying...';

    const response = await authFetch('/audit-log/verify');
    if (!response.ok) {
        resultEl.innerText = 'Verification request failed: ' + response.status;
        return;
    }

    const result = await response.json();
    if (result.intact) {
        resultEl.innerText = `Chain intact -- ${result.verified_count} row(s) verified from id ${result.checked_from_id} onward.`;
    } else {
        resultEl.innerText =
            `CHAIN BROKEN at row ${result.first_broken_id} (${result.reason}) -- ` +
            `${result.verified_count} row(s) before it verified correctly.`;
        resultEl.style.color = 'var(--blood-bright)';
    }
}

async function loadLogCheckpoints() {
    const response = await authFetch('/logs/checkpoints');
    if (!response.ok) return;
    const checkpoints = await response.json();

    const tbody = document.getElementById('checkpoint-rows');
    tbody.innerHTML = '';
    for (const cp of checkpoints) {
        const row = document.createElement('tr');

        const timeCell = document.createElement('td');
        timeCell.textContent = new Date(cp.computed_at).toLocaleString();
        const rangeCell = document.createElement('td');
        rangeCell.textContent = `${cp.range_start_id}–${cp.range_end_id}`;
        const countCell = document.createElement('td');
        countCell.textContent = cp.row_count;
        const statusCell = document.createElement('td');
        const pill = document.createElement('span');
        pill.textContent = cp.status === 'verified' ? 'Verified' : cp.status === 'broken' ? 'Broken' : 'Unverifiable';
        pill.className = 'status-pill status-review-' + (cp.status === 'verified' ? 'reviewed' : cp.status === 'broken' ? 'open' : 'false-positive');
        statusCell.appendChild(pill);

        row.appendChild(timeCell);
        row.appendChild(rangeCell);
        row.appendChild(countCell);
        row.appendChild(statusCell);
        tbody.appendChild(row);
    }
}

async function loadAuditLog() {
    const offset = auditLogPage * AUDIT_LOG_PAGE_SIZE;
    const response = await authFetch(`/audit-log?limit=${AUDIT_LOG_PAGE_SIZE}&offset=${offset}`);
    if (!response.ok) return;

    const data = await response.json();
    auditLogTotal = data.total;

    const tbody = document.getElementById('audit-log-rows');
    tbody.innerHTML = '';
    for (const entry of data.entries) {
        const row = document.createElement('tr');

        const timeCell = document.createElement('td');
        timeCell.textContent = new Date(entry.occurred_at).toLocaleString();
        const actorCell = document.createElement('td');
        actorCell.textContent = entry.actor_username;
        const actionCell = document.createElement('td');
        actionCell.textContent = entry.action;
        const resourceCell = document.createElement('td');
        resourceCell.textContent = entry.resource || '—';
        const outcomeCell = document.createElement('td');
        outcomeCell.textContent = entry.outcome;
        outcomeCell.className = entry.outcome === 'success' ? 'level-Low' : 'level-High';
        const ipCell = document.createElement('td');
        ipCell.textContent = entry.source_ip;
        const detailsCell = document.createElement('td');
        detailsCell.textContent = entry.details || '';

        row.appendChild(timeCell);
        row.appendChild(actorCell);
        row.appendChild(actionCell);
        row.appendChild(resourceCell);
        row.appendChild(outcomeCell);
        row.appendChild(ipCell);
        row.appendChild(detailsCell);
        tbody.appendChild(row);
    }

    const totalPages = Math.max(1, Math.ceil(auditLogTotal / AUDIT_LOG_PAGE_SIZE));
    document.getElementById('audit-log-page-info').textContent =
        `Page ${auditLogPage + 1} of ${totalPages} (${auditLogTotal} total)`;
    document.getElementById('audit-log-prev').disabled = auditLogPage <= 0;
    document.getElementById('audit-log-next').disabled = auditLogPage + 1 >= totalPages;
}

async function changeAuditLogPage(delta) {
    auditLogPage += delta;
    await loadAuditLog();
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

// ---------- Correlation Rules ----------

async function loadCorrelationLabels() {
    const response = await authFetch('/correlation-rules/labels');
    if (!response.ok) return;
    const labels = await response.json();

    const select = document.getElementById('corr-label');
    select.innerHTML = '';
    for (const label of labels) {
        const opt = document.createElement('option');
        opt.value = label;
        opt.textContent = label;
        select.appendChild(opt);
    }
}

async function loadCorrelationRules() {
    const response = await authFetch('/correlation-rules');
    if (!response.ok) return;
    const rules = await response.json();

    const tbody = document.getElementById('corr-rule-rows');
    tbody.innerHTML = '';

    for (const rule of rules) {
        const row = document.createElement('tr');

        const nameCell = document.createElement('td');
        nameCell.textContent = rule.name;
        const labelCell = document.createElement('td');
        labelCell.textContent = rule.match_label;
        const groupCell = document.createElement('td');
        groupCell.textContent = rule.group_by;
        const thresholdCell = document.createElement('td');
        thresholdCell.textContent = rule.threshold_count;
        const windowCell = document.createElement('td');
        windowCell.textContent = rule.window_minutes + ' min';
        const severityCell = document.createElement('td');
        severityCell.textContent = rule.alert_severity;

        const enabledCell = document.createElement('td');
        const enabledToggle = document.createElement('input');
        enabledToggle.type = 'checkbox';
        enabledToggle.checked = rule.enabled;
        enabledToggle.onchange = () => toggleCorrelationRule(rule, enabledToggle.checked);
        enabledCell.appendChild(enabledToggle);

        const actionCell = document.createElement('td');
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Remove';
        delBtn.style.background = 'transparent';
        delBtn.style.borderColor = 'var(--border)';
        delBtn.style.color = 'var(--text-dim)';
        delBtn.onclick = () => deleteCorrelationRule(rule.id);
        actionCell.appendChild(delBtn);

        row.append(nameCell, labelCell, groupCell, thresholdCell, windowCell, severityCell, enabledCell, actionCell);
        tbody.appendChild(row);
    }
}

async function createCorrelationRule() {
    const resultEl = document.getElementById('corr-result');
    const payload = {
        name: document.getElementById('corr-name').value.trim(),
        match_label: document.getElementById('corr-label').value,
        group_by: document.getElementById('corr-group-by').value,
        threshold_count: parseInt(document.getElementById('corr-threshold').value, 10),
        window_minutes: parseInt(document.getElementById('corr-window').value, 10),
        alert_severity: document.getElementById('corr-severity').value,
        enabled: true,
    };

    if (!payload.name || !payload.match_label || !(payload.threshold_count >= 2) || !(payload.window_minutes >= 1)) {
        resultEl.innerText = 'Name a rule, and use a threshold of at least 2 over at least 1 minute.';
        return;
    }

    const response = await authFetch('/correlation-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (response.ok) {
        resultEl.innerText = '';
        document.getElementById('corr-name').value = '';
        loadCorrelationRules();
    } else {
        resultEl.innerText = 'Failed to add rule: ' + response.status;
    }
}

async function toggleCorrelationRule(rule, enabled) {
    await authFetch(`/correlation-rules/${rule.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...rule, enabled })
    });
}

async function deleteCorrelationRule(id) {
    if (!confirm('Remove this correlation rule?')) return;
    const response = await authFetch(`/correlation-rules/${id}`, { method: 'DELETE' });
    if (response.ok) loadCorrelationRules();
}

// ---------- Notifications ----------
const CHANNEL_FIELD_DEFS = {
    email: [
        { key: 'smtp_host', placeholder: 'SMTP host (e.g. smtp.gmail.com)' },
        { key: 'smtp_port', placeholder: 'SMTP port (e.g. 587)', type: 'number' },
        { key: 'username', placeholder: 'SMTP username' },
        { key: 'password', placeholder: 'SMTP password', type: 'password' },
        { key: 'from', placeholder: 'From address' },
        { key: 'to', placeholder: 'To address' },
    ],
    slack: [{ key: 'webhook_url', placeholder: 'Slack webhook URL' }],
    discord: [{ key: 'webhook_url', placeholder: 'Discord webhook URL' }],
    telegram: [
        { key: 'bot_token', placeholder: 'Bot token' },
        { key: 'chat_id', placeholder: 'Chat ID' },
    ],
    ntfy: [
        { key: 'server_url', placeholder: 'ntfy server URL (e.g. https://ntfy.sh)' },
        { key: 'topic', placeholder: 'Topic' },
    ],
    webhook: [{ key: 'url', placeholder: 'Webhook URL' }],
};

function renderChannelFields() {
    const kind = document.getElementById('channel-kind').value;
    const container = document.getElementById('channel-fields');
    container.innerHTML = '';

    for (const field of CHANNEL_FIELD_DEFS[kind]) {
        const input = document.createElement('input');
        input.id = `channel-field-${field.key}`;
        input.placeholder = field.placeholder;
        input.type = field.type || 'text';
        container.appendChild(input);
    }
}

async function loadNotificationChannels() {
    const response = await authFetch('/notifications');
    if (!response.ok) return;
    const channels = await response.json();

    const tbody = document.getElementById('channel-rows');
    tbody.innerHTML = '';

    for (const ch of channels) {
        const row = document.createElement('tr');

        const nameCell = document.createElement('td');
        nameCell.textContent = ch.name;
        const kindCell = document.createElement('td');
        kindCell.textContent = ch.kind;
        const sevCell = document.createElement('td');
        sevCell.textContent = ch.min_severity;

        const testCell = document.createElement('td');
        const testBtn = document.createElement('button');
        testBtn.textContent = 'Test';
        testBtn.onclick = () => testNotificationChannel(ch.id, testBtn);
        testCell.appendChild(testBtn);

        const deleteCell = document.createElement('td');
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Remove';
        delBtn.onclick = () => deleteNotificationChannel(ch.id);
        deleteCell.appendChild(delBtn);

        row.appendChild(nameCell);
        row.appendChild(kindCell);
        row.appendChild(sevCell);
        row.appendChild(testCell);
        row.appendChild(deleteCell);
        tbody.appendChild(row);
    }
}

async function createNotificationChannel() {
    const name = document.getElementById('channel-name').value.trim();
    const kind = document.getElementById('channel-kind').value;
    const minSeverity = document.getElementById('channel-min-severity').value;

    if (!name) {
        document.getElementById('channel-result').innerText = 'Channel name is required.';
        return;
    }

    const config = {};
    for (const field of CHANNEL_FIELD_DEFS[kind]) {
        const el = document.getElementById(`channel-field-${field.key}`);
        let value = el.value;
        if (field.type === 'number') value = parseInt(value, 10) || 0;
        config[field.key] = value;
    }

    const response = await authFetch('/notifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind, name, config, min_severity: minSeverity })
    });

    if (response.ok) {
        document.getElementById('channel-result').innerText = 'Channel added.';
        document.getElementById('channel-name').value = '';
        loadNotificationChannels();
    } else {
        document.getElementById('channel-result').innerText = 'Failed: ' + response.status;
    }
}

async function deleteNotificationChannel(id) {
    if (!confirm('Remove this notification channel?')) return;
    const response = await authFetch(`/notifications/${id}`, { method: 'DELETE' });
    if (response.ok) loadNotificationChannels();
    else alert('Failed to remove channel: ' + response.status);
}

async function testNotificationChannel(id, btn) {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = 'Sending...';

    const response = await authFetch(`/notifications/${id}/test`, { method: 'POST' });

    btn.disabled = false;
    btn.textContent = response.ok ? 'Sent!' : 'Failed';
    setTimeout(() => { btn.textContent = original; }, 2000);
}

// ---------- Syslog ----------

async function initSyslogPage() {
    const meResp = await authFetch('/me');
    const me = await meResp.json();

    if (me.role !== 'admin') {
        document.getElementById('syslog-access-result').innerText = 'Access denied: admin only.';
        return;
    }

    document.getElementById('syslog-content').style.display = 'block';
    loadSyslogConfig();
}

async function loadSyslogConfig() {
    const response = await authFetch('/syslog/config');
    if (!response.ok) return;
    const cfg = await response.json();

    document.getElementById('syslog-udp-toggle').checked = cfg.enabled_udp;
    document.getElementById('syslog-tcp-toggle').checked = cfg.enabled_tcp;
    document.getElementById('syslog-allowed-cidrs').value = cfg.allowed_cidrs;

    const lastEl = document.getElementById('syslog-last-message');
    lastEl.innerText = cfg.last_message_at
        ? `Last message received ${formatDirectoryTimestamp(cfg.last_message_at)} from ${cfg.last_message_host}.`
        : 'No messages received yet.';
}

async function saveSyslogConfig() {
    const payload = {
        enabled_udp: document.getElementById('syslog-udp-toggle').checked,
        enabled_tcp: document.getElementById('syslog-tcp-toggle').checked,
        allowed_cidrs: document.getElementById('syslog-allowed-cidrs').value,
    };

    const response = await authFetch('/syslog/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    const resultEl = document.getElementById('syslog-config-result');
    if (response.ok) {
        resultEl.innerText = 'Saved.';
        loadSyslogConfig();
    } else if (response.status === 400) {
        resultEl.innerText = 'One of the allowed CIDRs/IPs is not valid -- check each line.';
    } else {
        resultEl.innerText = 'Save failed: ' + response.status;
    }
}
