function renderSidebar() {
    const links = [
        { path: '/dashboard', label: 'Dashboard' },
        { path: '/agents', label: 'Agents' },
        { path: '/syslog', label: 'Syslog' },
        { path: '/audit-log', label: 'Audit Log' },
        { path: '/settings', label: 'Settings' },
    ];

    const bar = document.createElement('div');
    bar.className = 'topbar';

    const title = document.createElement('div');
    title.className = 'topbar-title';
    title.textContent = 'SECLOG';
    bar.appendChild(title);

    const nav = document.createElement('nav');
    nav.className = 'topbar-nav';
    for (const link of links) {
        const a = document.createElement('a');
        a.href = '#' + link.path;
        a.textContent = link.label;
        a.setAttribute('data-route', link.path);
        a.onclick = (e) => { e.preventDefault(); navigateTo(link.path); };
        nav.appendChild(a);
    }
    bar.appendChild(nav);

    const logoutLink = document.createElement('a');
    logoutLink.href = '#';
    logoutLink.textContent = 'Logout';
    logoutLink.className = 'topbar-logout';
    logoutLink.onclick = (e) => { e.preventDefault(); logout(); };
    bar.appendChild(logoutLink);

    document.body.prepend(bar);
}
