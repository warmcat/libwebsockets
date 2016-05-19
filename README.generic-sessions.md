Generic Sessions Plugin
-----------------------

Enabling for build
------------------

Enable at CMake with -DLWS_WITH_GENERIC_SESSIONS=1

This also needs sqlite3 (libsqlite3-dev or similar package)


Introduction
------------

The generic-sessions protocol plugin provides cookie-based login
authentication for lws web and ws connections.

The plugin handles everything about generic account registration,
email verification, lost password, and other generic account
management.

Other code, in another eg, ws protocol handler, only needs very high-level
state information from generic-sessions, ie, which user the client is
authenticated as.  Everything underneath is managed in generic-sessions.


 - random 20-byte session id managed in a cookie

 - all information related to the session held at the server, nothing managed clientside

 - sqlite3 used at the server to manage active sessions and users

 - defaults to creating anonymous sessions with no user associated

 - admin account (with user-selectable username) is defined in config with a SHA-1 of the password; rest of the accounts are in sqlite3

 - login, logout, register account + email verification built-in with examples

 - in a mount, some file suffixes (ie, .js) can be associated with a protocol for the purposes of rewriting symbolnames.  These are read-only copies of logged-in server state.

 - When your page fetches .js or other rewritten files from that mount, "$lwsgs_user" and so on are rewritten on the fly using chunked transfer encoding

 - Eliminates server-side scripting with a few rewritten symbols and javascript on client side

 - 32-bit bitfield for authentication sectoring, mounts can provide a mask on the loggin-in session's associated server-side bitfield that must be set for access.

 - No code (just config) required for, eg, private URL namespace that requires login to access. 


Overall Flow
------------

When the protocol is initialized, it gets per-vhost information from the config, such
as where the sqlite3 databases are to be stored.  The admin username and sha-1 of the
admin password are also taken from here.

In the mounts using protocol-generic-sessions, a cookie is maintained against any requests;
if no cookie was active on the initial request a new session is created with no attached user.
So there should always be an active session after any transactions with the server.

In the example html going to the mount /lwsgs loads a login / register page as the default.

The <form> in the login page contains 'next url' hidden inputs that let the html 'program'
where the form handler will go after a successful admin login, a successful user login and
a failed login.

After a successful login, the sqlite record at the server for the current session is updated
to have the logged-in username associated with it. 

Configuration
------------

(subject to change...)

"auth-mask" defines the autorization sector bits that must be enabled on the session to gain access.

"auth-mask" 0 is the default.

  - b0 is set if you are logged in as a user at all.
  - b1 is set if you are logged in with the user configured to be admin
  - b2 is set if the account has been verified (the account configured for admin is always verified)

```
      {
        # things in here can always be served
        "mountpoint": "/lwsgs",
        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions",
        "origin": "callback://protocol-generic-sessions",
        "default": "generic-sessions-login-example.html",
        "auth-mask": "0",
        "interpret": {
                ".js": "protocol-generic-sessions"
        }
       }, {
        # things in here can only be served if logged in as a user
        "mountpoint": "/lwsgs/needauth",
        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions/needauth",
        "origin": "callback://protocol-generic-sessions",
        "default": "generic-sessions-login-example.html",
        "auth-mask": "5", # logged in as a verified user
        "interpret": {
                ".js": "protocol-generic-sessions"
        }
       }, {
        # things in here can only be served if logged in as admin
        "mountpoint": "/lwsgs/needadmin",
        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions/needadmin",
        "origin": "callback://protocol-generic-sessions",
        "default": "generic-sessions-login-example.html",
        "auth-mask": "7", # b2 = verified (by email / or admin), b1 = admin, b0 = logged in with any user name
        "interpret": {
                ".js": "protocol-generic-sessions"
        }
       }
```

The vhost configures the storage dir, admin credentials and session cookie lifetimes:

```
     "ws-protocols": [{
       "protocol-generic-sessions": {
         "status": "ok",
         "admin-user": "admin",

# create the pw hash like this (for the example pw, "jipdocesExunt" )
# $ echo -n "jipdocesExunt" | sha1sum
# 046ce9a9cca769e85798133be06ef30c9c0122c9 -
#
# Obviously ** change this password hash to a secret one before deploying **
#
         "admin-password-sha1": "046ce9a9cca769e85798133be06ef30c9c0122c9",
         "session-db": "/var/www/sessions/lws.sqlite3",
         "timeout-idle-secs": "600",
	 "timeout-anon-idle-secs": "1200",
         "timeout-absolute-secs": "6000",
# the confounder is part of the salted password hashes.  If this config
# file is in a 0700 root:root dir, an attacker with apache credentials
# will have to get the confounder out of the process image to even try
# to guess the password hashes.
         "confounder": "Change to <=31 chars of junk",

         "email-from": "noreply@example.com",
         "email-smtp-ip": "127.0.0.1",
         "email-expire": "3600",
         "email-helo": "myhost.com",
         "email-contact-person": "Set Me <real-person@email.com>",
         "email-confirm-url-base": "http://localhost:7681/lwsgs"
       }
```

The email- related settings control generation of automatic emails for
registration and forgotten password.

 - email-from: The email address automatic emails are sent from

 - email-smtp-ip: Normally 127.0.0.1, if you have a suitable server on port
   25 on your lan you can use this instead here.

 - email-expire: Seconds that links sent in email will work before being
   deleted

 - email-helo: HELO to use when communicating with your SMTP server

 - email-contact-person: mentioned in the automatic emails as a human who can
   answer questions

 - email-confirm-url-base: the URL to start links with in the emails, so the
   recipient can get back to the web server


Password Confounder
-------------------

You can also define a per-vhost confounder used when aggregating the password
with the salt when it is hashed.  Any attacker will also need to get the
confounder along with the database, which you can make harder by making the
config dir only eneterable / readable by root.


Preparing the db directory
--------------------------

You will have to prepare the db directory so it's suitable for the lwsws user to use,
that usually means apache, eg

```
# mkdir -p /var/www/sessions
# chown root:apache /var/www/sessions
# chmod 770 /var/www/sessions
```

Email configuration
-------------------

lwsgs will can send emails by talking to an SMTP server on localhost:25.  That
will usually be sendmail or postfix, you should confirm that works first by
itself using the `mail` application to send on it.

