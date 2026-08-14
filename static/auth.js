// Session state now lives in a server-set httpOnly cookie
// (__Host-seclog_session) -- JavaScript cannot read it, and doesn't need
// to. The browser attaches it automatically on same-origin requests.
// Real auth enforcement always happens server-side; this file just reacts
// to what the server tells us.

// Kept as a no-op so existing page scripts that call requireAuth() on
// load don't need to change. There's nothing for the client to check
// anymore -- if the cookie is missing/invalid, the first authFetch()
// call below will get a 401 and redirect.
function requireAuth() {}

// Wraps fetch() for calls to protected endpoints. Cookies are sent
// automatically for same-origin requests, so there's no token to attach
// by hand anymore.
async function authFetch(url, options = {}) {
	options.credentials = 'same-origin';
	const response = await fetch(url, options);

	// If the server says we're not authenticated (missing/expired/revoked
	// session), bounce back to login rather than showing a broken page.
	if (response.status === 401) {
		window.location.href = '/index.html';
	}
	return response;
}

async function logout() {
	// Tell the server to invalidate the session and clear the cookie.
	// Fire-and-forget is fine here -- we're navigating away regardless.
	try {
		await fetch('/logout', { method: 'POST', credentials: 'same-origin' });
	} finally {
		window.location.href = '/index.html';
	}
}
