Notes about generic-sessions Plugin
===================================

@section gseb Enabling lwsgs for build

Enable at CMake with -DLWS_WITH_GENERIC_SESSIONS=1

This also needs sqlite3 (libsqlite3-dev or similar package)


@section gsi lwsgs Introduction

The generic-sessions protocol plugin provides cookie-based login
authentication for lws web and ws connections.

The plugin handles everything about generic account registration,
email verification, lost password, account deletion, and other generic account
management.

Other code, in another eg, ws protocol handler, only needs very high-level
state information from generic-sessions, ie, which user the client is
authenticated as.  Everything underneath is managed in generic-sessions.


 - random 20-byte session id managed in a cookie

 - all information related to the session held at the server, nothing managed clientside

 - sqlite3 used at the server to manage active sessions and users

 - defaults to creating anonymous sessions with no user associated

 - admin account (with user-selectable username) is defined in config with a SHA-1 of the password; rest of the accounts are in sqlite3
 
 - user account passwords stored as salted SHA-1 with additional confounder
  only stored in the JSON config, not the database 

 - login, logout, register account + email verification built-in with examples

 - in a mount, some file suffixes (ie, .js) can be associated with a protocol for the purposes of rewriting symbolnames.  These are read-only copies of logged-in server state.

 - When your page fetches .js or other rewritten files from that mount, "$lwsgs_user" and so on are rewritten on the fly using chunked transfer encoding

 - Eliminates server-side scripting with a few rewritten symbols and
 javascript on client side

 - 32-bit bitfield for authentication sectoring, mounts can provide a mask on the loggin-in session's associated server-side bitfield that must be set for access.

 - No code (just config) required for, eg, private URL namespace that requires login to access. 
 

@section gsin Lwsgs Integration to HTML

Only three steps are needed to integrate lwsgs in your HTML.

1) lwsgs HTML UI is bundled with the javascript it uses in `lwsgs.js`, so
import that script file in your head section

2) define an empty div of id "lwsgs" somewhere

3) Call lwsgs_initial() in your page

That's it.  An example is below

```
	<html>
	 <head>
	  <script src="lwsgs.js"></script>
	  <style>
	     .body { font-size: 12 }
	     .gstitle { font-size: 18 }
	  </style>
	  </head>
	  <body style="background-image:url(seats.jpg)">
	    <table style="width:100%;transition: max-height 2s;">
	     <tr>
	      <td style="vertical-align:top;text-align:left;width=200px">
	       <img src="lwsgs-logo.png">
	      </td>
	      <td style="vertical-align:top;float:right">
		<div id=lwsgs style="text-align:right;background-color: rgba(255, 255, 255, 0.8);"></div>
	      </td>
	     </tr>
	    </table>
	   </form>
	   
	   <script>lwsgs_initial();</script>
	
	 </body>
	</html>
```

@section gsof Lwsgs Overall Flow@

When the protocol is initialized, it gets per-vhost information from the config, such
as where the sqlite3 databases are to be stored.  The admin username and sha-1 of the
admin password are also taken from here.

In the mounts using protocol-generic-sessions, a cookie is maintained against any requests; if no cookie was active on the initial request a new session is
created with no attached user.

So there should always be an active session after any transactions with the server.

In the example html going to the mount /lwsgs loads a login / register page as the default.

The <form> in the login page contains 'next url' hidden inputs that let the html 'program' where the form handler will go after a successful admin login, a successful user login and a failed login.

After a successful login, the sqlite record at the server for the current session is updated to have the logged-in username associated with it. 



@section gsconf Lwsgs Configuration

"auth-mask" defines the authorization sector bits that must be enabled on the session to gain access.

"auth-mask" 0 is the default.

  - b0 is set if you are logged in as a user at all.
  - b1 is set if you are logged in with the user configured to be admin
  - b2 is set if the account has been verified (the account configured for admin is always verified)
  - b3 is set if your session just did the forgot password flow successfully

```
	      {
	        # things in here can always be served
	        "mountpoint": "/lwsgs",
	        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions",
	        "origin": "callback://protocol-lws-messageboard",
	        "default": "generic-sessions-login-example.html",
	        "auth-mask": "0",
	        "interpret": {
	                ".js": "protocol-lws-messageboard"
	        }
	       }, {
	        # things in here can only be served if logged in as a user
	        "mountpoint": "/lwsgs/needauth",
	        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions/needauth",
	        "origin": "callback://protocol-lws-messageboard",
	        "default": "generic-sessions-login-example.html",
	        "auth-mask": "5", # logged in as a verified user
	        "interpret": {
	                ".js": "protocol-lws-messageboard"
	        }
	       }, {
	        # things in here can only be served if logged in as admin
	        "mountpoint": "/lwsgs/needadmin",
	        "origin": "file:///usr/share/libwebsockets-test-server/generic-sessions/needadmin",
	        "origin": "callback://protocol-lws-messageboard",
	        "default": "generic-sessions-login-example.html",
	        "auth-mask": "7", # b2 = verified (by email / or admin), b1 = admin, b0 = logged in with any user name
	        "interpret": {
	                ".js": "protocol-lws-messageboard"
	        }
	       }
```
Note that the name of the real application protocol that uses generic-sessions
is used, not generic-sessions itself. 

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

 - `email-from`: The email address automatic emails are sent from

 - `email-smtp-ip`: Normally 127.0.0.1, if you have a suitable server on port
   25 on your lan you can use this instead here.

 - `email-expire`: Seconds that links sent in email will work before being
   deleted

 - `email-helo`: HELO to use when communicating with your SMTP server

 - `email-contact-person`: mentioned in the automatic emails as a human who can
   answer questions

 - `email-confirm-url-base`: the URL to start links with in the emails, so the
   recipient can get back to the web server
   
The real protocol that makes use of generic-sessions must also be listed and
any configuration it needs given

```
	       "protocol-lws-messageboard": {
	         "status": "ok",
	         "message-db": "/var/www/sessions/messageboard.sqlite3"
	       },
```

Notice the real application uses his own sqlite db, no details about how
generic-sessions works or how it stores data are available to it.


@section gspwc Lwsgs Password Confounder

You can also define a per-vhost confounder shown in the example above, used
when aggregating the password with the salt when it is hashed.  Any attacker
will also need to get the confounder along with the database, which you can
make harder by making the config dir only eneterable / readable by root.


@section gsprep Lwsgs Preparing the db directory

You will have to prepare the db directory so it's suitable for the lwsws user to use,
that usually means apache, eg

```
	# mkdir -p /var/www/sessions
	# chown root:apache /var/www/sessions
	# chmod 770 /var/www/sessions
```

@section gsrmail Lwsgs Email configuration

lwsgs will can send emails by talking to an SMTP server on localhost:25.  That
will usually be sendmail or postfix, you should confirm that works first by
itself using the `mail` application to send on it.

lwsgs has been tested on stock Fedora sendmail and postfix.


@section gsap Lwsgs Integration with another protocol

lwsgs is designed to provide sessions and accounts in a standalone and generic way.

But it's not useful by itself, there will always be the actual application who wants
to make use of generic-sessions features.

We provide the "messageboard" plugin as an example of how to integrate with
your actual application protocol.

The basic approach is the 'real' protocol handler (usually a plugin itself)
subclasses the generic-sessions plugin and calls through to it by default.

The "real" protocol handler entirely deals with ws-related stuff itself, since
generic-sessions does not use ws.  But for

 - LWS_CALLBACK_HTTP
 - LWS_CALLBACK_HTTP_BODY
 - LWS_CALLBACK_HTTP_BODY_COMPLETION
 - LWS_CALLBACK_HTTP_DROP_PROTOCOL
 
the "real" protocol handler checks if it recognizes the activity (eg, his own
POST form URL) and if not, passes stuff through to the generic-sessions protocol callback to handle it.  To simplify matters the real protocol can just pass
through any unhandled messages to generic-sessions.

The "real" protocol can get a pointer to generic-sessions protocol on the
same vhost using

```
	vhd->gsp = lws_vhost_name_to_protocol(vhd->vh, "protocol-generic-sessions");
```

The "real" protocol must also arrange generic-sessions per_session_data in his
own per-session allocation.  To allow keeping generic-sessions opaque, the
real protocol must allocate that space at runtime, using the pss size
the generic-sessions protocol struct exposes

```
	struct per_session_data__myapp {
		void *pss_gs;
	...
	
		pss->pss_gs = malloc(vhd->gsp->per_session_data_size);
```

The allocation reserved for generic-sessions is then used as user_space when
the real protocol calls through to the generic-sessions callback

```
	vhd->gsp->callback(wsi, reason, &pss->pss_gs, in, len);
```

In that way the "real" protocol can subclass generic-sessions functionality.


To ease management of these secondary allocations, there are callbacks that
occur when a wsi binds to a protocol and when the binding is dropped.  These
should be used to malloc and free and kind of per-connection
secondary allocations.

```
	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (!pss || pss->pss_gs)
			break;

		pss->pss_gs = malloc(vhd->gsp->per_session_data_size);
		if (!pss->pss_gs)
			return -1;

		memset(pss->pss_gs, 0, vhd->gsp->per_session_data_size);
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (vhd->gsp->callback(wsi, reason, pss ? pss->pss_gs : NULL, in, len))
			return -1;

		if (pss->pss_gs) {
			free(pss->pss_gs);
			pss->pss_gs = NULL;
		}
		break;
```


#section gsapsib Getting session-specific information from another protocol

At least at the time when someone tries to upgrade an http(s) connection to
ws(s) with your real protocol, it is necessary to confirm the cookie the http(s)
connection has with generic-sessions and find out his username and other info.

Generic sessions lets another protocol check it again by calling his callback,
and lws itself provides a generic session info struct to pass the related data

```
	struct lws_session_info {
		char username[32];
		char email[100];
		char ip[72];
		unsigned int mask;
		char session[42];
	};

	struct lws_session_info sinfo;
	...
	vhd->gsp->callback(wsi, LWS_CALLBACK_SESSION_INFO,
				   &pss->pss_gs, &sinfo, 0);
```

After the call to generic-sessions, the results can be

 -  all the strings will be zero-length and .mask zero, there is no usable cookie
 
  - only .ip and .session are set: the cookie is OK but no user logged in
  
  - all the strings contain information about the logged-in user

the real protocol can use this to reject attempts to open ws connections from
http connections that are not authenticated; afterwards there's no need to
check the ws connection auth status again.

