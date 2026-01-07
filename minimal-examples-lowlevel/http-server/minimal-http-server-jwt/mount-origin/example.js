document.addEventListener('DOMContentLoaded', function() {
    // Check for our specific cookie to update UI presentation
    // This is purely for client-side display logic.
    // Real security happens on the server.
    
    function getCookie(name) {
        let value = "; " + document.cookie;
        let parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop().split(";").shift();
    }

    // We look for the JWT cookie. In a real app, you might not be able to read 
    // HttpOnly cookies from JS. However, often a separate non-HttpOnly flag cookie 
    // is set, or we just try to fetch the secret and fail if not auth'd.
    // For this example, we'll try to fetch the secret api.

    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
        const errorDiv = document.getElementById('error-message');
        if (errorDiv) {
            let msg = "An error occurred.";
            if (error === 'invalid_credentials') msg = "Invalid username or password.";
            if (error === 'unauthorized') msg = "You must be logged in to view this content.";
            errorDiv.textContent = msg;
            errorDiv.classList.remove('hidden');
        }
        // Optional: clear the query string without reloading
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    fetch('/api/secret')
        .then(response => {
            if (response.status === 200) {
                return response.json();
            } else {
                throw new Error('Not authenticated');
            }
        })
        .then(data => {
            // Authenticated
            document.getElementById('unauth-view').classList.add('hidden');
            document.getElementById('auth-view').classList.remove('hidden');
            document.getElementById('user-display').textContent = data.user;
            document.getElementById('secret-content').textContent = JSON.stringify(data, null, 2);
        })
        .catch(err => {
            // Not authenticated
            document.getElementById('unauth-view').classList.remove('hidden');
            document.getElementById('auth-view').classList.add('hidden');
        });
});
