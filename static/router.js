const routes = {
    '/dashboard': { fragment: 'pages/dashboard.html', init: 'initDashboard' },
    '/agents': { fragment: 'pages/agents.html', init: 'initAgents' },
    '/directory': { fragment: 'pages/directory.html', init: 'initDirectory' },
    '/syslog': { fragment: 'pages/syslog.html', init: 'initSyslogPage' },
    '/audit-log': { fragment: 'pages/audit-log.html', init: 'initAuditLogPage' },
    '/settings': { fragment: 'pages/settings.html', init: 'initSettings' },
};

// Fetches a content fragment and swaps it into #content, without a full
// page reload. pushState updates the URL (so refresh/back/forward still
// work) without actually navigating the browser.
async function navigateTo(path, pushState = true) {
    const route = routes[path];
    if (!route) return;

    const resp = await fetch(route.fragment);
    document.getElementById('content').innerHTML = await resp.text();

    // The fragment's markup now exists in the DOM -- safe to run its
    // page-specific setup function.
    if (window[route.init]) window[route.init]();

    updateActiveNav(path);
    if (pushState) history.pushState({ path }, '', '#' + path);
}

// Handles the browser's own Back/Forward buttons.
window.addEventListener('popstate', (e) => {
    const path = (e.state && e.state.path) || '/dashboard';
    navigateTo(path, false);
});

function updateActiveNav(path) {
    document.querySelectorAll('.sidebar a[data-route]').forEach(a => {
        a.classList.toggle('active', a.getAttribute('data-route') === path);
    });
}
