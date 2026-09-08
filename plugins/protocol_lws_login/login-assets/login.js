/*
 * The ?error= urlarg is fully attacker-chosen: anybody can hand a victim
 * a link to this page.  It therefore only ever selects one of a fixed
 * set of messages by code, and never supplies the message text itself --
 * textContent keeps injected markup inert, but arbitrary attacker text
 * rendered in the error box of a real login form ("your session was
 * terminated, call +1-555-...") is a convincing phishing surface on its
 * own.  Anything unrecognised gets the generic message.
 *
 * URLSearchParams.get() has already percent-decoded the value, so there
 * is deliberately no decodeURIComponent() here: a second decode both
 * changes the string and throws URIError on a lone '%'.
 */
const lwsLoginErrors = {
    invalid_credentials: 'Login failed: check your username and password.',
    session_expired: 'Your session has expired, please log in again.',
    access_denied: 'You are not authorized to view that page.',
    server_error: 'The login service is temporarily unavailable.'
};

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
        const errorMsg = document.getElementById('error-msg');
        /*
         * hasOwnProperty, not a bare lookup: 'constructor' and friends
         * are inherited properties and would otherwise be rendered.
         */
        const known = Object.prototype.hasOwnProperty.call(lwsLoginErrors,
                                                           error);
        if (errorMsg)
            errorMsg.textContent = known ? lwsLoginErrors[error] :
                                           'Login failed.';
    }
});
