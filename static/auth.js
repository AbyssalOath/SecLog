// Cookies are httpOnly now -- JS can't read the session token at all,
// and doesn't need to. `credentials: 'include'` tells fetch to send
// the browser's cookies automatically on same-origin requests.
function requireAuth() {
    // No client-readable token to check anymore. Just attempt the page;
    // the first authFetch call will redirect to login if the cookie
    // is missing/invalid.
}

async function authFetch(url, options = {}) {
    options.credentials = 'include';
    const response = await fetch(url, options);

    if (response.status === 401) {
        window.location.href = '/index.html';
    }
    return response;
}

async function logout() {
    await fetch('/logout', { method: 'POST', credentials: 'include' });
    window.location.href = '/index.html';
}
