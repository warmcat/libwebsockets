<!-- lwsgs rewrites the below $vars $v $v into the correct values on the fly -->

var lwsgs_user = "$lwsgs_user";
var lwsgs_auth = "$lwsgs_auth";
var lwsgs_email = "$lwsgs_email";

var lwsgs_html = '\
	<div id="dlogin" class="hidden"> \
        <form action="lwsgs-login" method="post"> \
         <input type="hidden" name="admin" value="needadmin/admin-login.html"> \
         <input type="hidden" name="good" value="index.html"> \
         <input type="hidden" name="bad" value="failed-login.html"> \
         <input type="hidden" name="forgot-good" value="sent-forgot-ok.html"> \
         <input type="hidden" name="forgot-bad" value="sent-forgot-fail.html">\
         <input type="hidden" name="forgot-post-good" value="post-forgot-ok.html">\
         <input type="hidden" name="forgot-post-bad" value="post-forgot-fail.html">\
	 <table class="r">\
          <tr>\
           <td>User Name\
            <input type="text" size="10" id="username" name="username"></td>\
           <td>Password\
            <input type="password" id="password" size="10" name="password"><div id="pw1"></div></td>\
	     </tr><tr>\
	   <td colspan="2" class="c">\
	<input type="submit" id="login" name="login" value="Login" class="em">\
      &nbsp;<input type="submit" id="forgot" name="forgot" value="Forgot password">\
           &nbsp;<input id="doreg" type="button" value="Sign up"></td>\
          </tr>\
         </table>\
        </form>\
       </div>\
\
       <div id="dlogout" class="hiddenr">\
        <form action="lwsgs-logout" method="post" class="r">\
         <input type="hidden" name="good" value="index.html">\
         <table class="r">\
          <tr><td><table><tr><td><span id=grav></span></td></tr><tr><td>\
	<a href="#" id="clink">\
	<span id="curuser"></span></a></td></tr></table></td>\
           <td class="tac"><input type="submit" name="logout" value="Logout"></td>\
          </tr></table></td></tr>\
         </table>\
        </form></div>\
\
	<div id="dregister" class="hidden">\
	 <form action="lwsgs-login" method="post">\
	  <input type="hidden" name="admin" value="needadmin/admin-login.html">\
	  <input type="hidden" name="good" value="successful-login.html">\
	  <input type="hidden" name="bad" value="failed-login.html">\
	  <input type="hidden" name="reg-good" value="post-register-ok.html">\
	  <input type="hidden" name="reg-bad" value="post-register-fail.html">\
	  <input type="hidden" name="forgot-good" value="sent-forgot-ok.html">\
	  <input type="hidden" name="forgot-bad" value="sent-forgot-fail.html">\
	  <input type="hidden" name="forgot-post-good" value="post-forgot-ok.html">\
	  <input type="hidden" name="forgot-post-bad" value="post-forgot-fail.html">\
	  <table class="l">\
	     <tr>\
	      <td colspan=2 align=center>\
		<span id="curuser"></span>\
	       <b>Please enter your details to register</b>:\
	      </td>\
	     </tr>\
	    <tr><td align=right>\
	     User Name:</td>\
	     <td><input type="text" size="10" id="rusername" name="username" &nbsp;<span id=uchk></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Password:</td>\
	     <td><input type="password" size="10" id="rpassword" name="password">&nbsp;<span id="rpw1"></span></td>\
	    </tr>\
	    <tr>\
	    </tr>\
	    <tr>\
	     <td align=right><span id="pw2">Password (again):</span></td>\
	     <td><input type="password" size="10" id="password2" name="password2">&nbsp;<span id="match"></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Email:</td>\
	     <td><input type="email" size="10" id="email" name="email"\
	          placeholder="me@example.com" &nbsp;<span id=echk></span></td>\
	    </tr>\
	    <tr>\
	     <td colspan=2 align=center>\
<input type="submit" id="register" name="register" value="Register" >\
<input type="submit" id="rforgot" name="forgot" value="Forgot Password" class="hidden">\
<input type="button" id="cancel" name="cancel" value="Cancel">\
	     </td>\
	    </tr>\
         </table>\
        </form>\
       </div>\
       \
       <div id="dchange" class="hidden">\
        <form action="lwsgs-change" method="post">\
         <input type="hidden" id="cusername" name="username">\
         <input type="hidden" name="admin" value="needadmin/admin-login.html">\
         <input type="hidden" name="good" value="index.html">\
         <input type="hidden" name="bad" value="failed-login.html">\
         <input type="hidden" name="reg-good" value="post-register-ok.html">\
         <input type="hidden" name="reg-bad" value="post-register-fail.html">\
         <input type="hidden" name="forgot-good" value="sent-forgot-ok.html">\
         <input type="hidden" name="forgot-bad" value="sent-forgot-fail.html">\
         <input type="hidden" name="forgot-post-good" value="post-forgot-ok.html">\
         <input type="hidden" name="forgot-post-bad" value="post-forgot-fail.html">\
         <table class="l">\
	     <tr>\
	      <td colspan=2 align=center>\
		<span id="ccuruser"></span>\
	       <b>Please enter your details to change</b>:\
	      </td>\
	     </tr>\
	    <tr><td align=right id="ccurpw_name">\
	     Current Password:</td>\
	     <td><input type="password" size="10" id="ccurpw" name="curpw"\
	         >&nbsp;<span id=cuchk></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Password:</td>\
	     <td><input type="password" size="10" id="cpassword" name="password"\
	          &nbsp;<span id="cpw1"></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right><span id="pw2">Password (again)</span></td>\
	     <td><input type="password" size="10" id="cpassword2" name="password2"\
	         >&nbsp;<span id="cmatch"></span></td>\
	    </tr>\
	<!-- not supported yet\
	    <tr>\
	     <td align=right id="cemail_name">Email:</td>\
	     <td><input type="email" size="10" id="cemail" name="email"\
	     	  placeholder="?" \
	     	  &nbsp;<span id=cechk></span></td>\
	    </tr> -->\
	    <tr>\
	     <td colspan=2 align=center>\
	      <input type="submit" id="change" name="change"\
	       value="Change" class="wide">\
	      <input type="submit" id="cforgot" name="forgot"\
	       value="Forgot Password" class="wide hidden">\
	      <input type="button" id="cancel2" name="cancel"\
	       value="Cancel" class="wide">\
	     </td>\
	    </tr>\
	    <tr>\
	     <td colspan=2>\
	      <input type="checkbox" id="showdel" name="showdel"\
	       > Show Delete&nbsp;\
	      <input type="submit" id="delete" name="delete" \
	       value="Delete Account" class="wide hidden">\
	     </td>\
	    </tr>\
         </table>\
        </form>\
       </div>\
       \
       <div id="dadmin" class="hidden">\
         Admin settings TBD\
       </div>\
';

/*-- this came from
  -- https://raw.githubusercontent.com/blueimp/JavaScript-MD5/master/js/md5.min.js
  -- under MIT license */
!function(n){"use strict";function t(n,t){var r=(65535&n)+(65535&t),e=(n>>16)+(t>>16)+(r>>16);return e<<16|65535&r}function r(n,t){return n<<t|n>>>32-t}function e(n,e,o,u,c,f){return t(r(t(t(e,n),t(u,f)),c),o)}function o(n,t,r,o,u,c,f){return e(t&r|~t&o,n,t,u,c,f)}function u(n,t,r,o,u,c,f){return e(t&o|r&~o,n,t,u,c,f)}function c(n,t,r,o,u,c,f){return e(t^r^o,n,t,u,c,f)}function f(n,t,r,o,u,c,f){return e(r^(t|~o),n,t,u,c,f)}function i(n,r){n[r>>5]|=128<<r%32,n[(r+64>>>9<<4)+14]=r;var e,i,a,h,d,l=1732584193,g=-271733879,v=-1732584194,m=271733878;for(e=0;e<n.length;e+=16)i=l,a=g,h=v,d=m,l=o(l,g,v,m,n[e],7,-680876936),m=o(m,l,g,v,n[e+1],12,-389564586),v=o(v,m,l,g,n[e+2],17,606105819),g=o(g,v,m,l,n[e+3],22,-1044525330),l=o(l,g,v,m,n[e+4],7,-176418897),m=o(m,l,g,v,n[e+5],12,1200080426),v=o(v,m,l,g,n[e+6],17,-1473231341),g=o(g,v,m,l,n[e+7],22,-45705983),l=o(l,g,v,m,n[e+8],7,1770035416),m=o(m,l,g,v,n[e+9],12,-1958414417),v=o(v,m,l,g,n[e+10],17,-42063),g=o(g,v,m,l,n[e+11],22,-1990404162),l=o(l,g,v,m,n[e+12],7,1804603682),m=o(m,l,g,v,n[e+13],12,-40341101),v=o(v,m,l,g,n[e+14],17,-1502002290),g=o(g,v,m,l,n[e+15],22,1236535329),l=u(l,g,v,m,n[e+1],5,-165796510),m=u(m,l,g,v,n[e+6],9,-1069501632),v=u(v,m,l,g,n[e+11],14,643717713),g=u(g,v,m,l,n[e],20,-373897302),l=u(l,g,v,m,n[e+5],5,-701558691),m=u(m,l,g,v,n[e+10],9,38016083),v=u(v,m,l,g,n[e+15],14,-660478335),g=u(g,v,m,l,n[e+4],20,-405537848),l=u(l,g,v,m,n[e+9],5,568446438),m=u(m,l,g,v,n[e+14],9,-1019803690),v=u(v,m,l,g,n[e+3],14,-187363961),g=u(g,v,m,l,n[e+8],20,1163531501),l=u(l,g,v,m,n[e+13],5,-1444681467),m=u(m,l,g,v,n[e+2],9,-51403784),v=u(v,m,l,g,n[e+7],14,1735328473),g=u(g,v,m,l,n[e+12],20,-1926607734),l=c(l,g,v,m,n[e+5],4,-378558),m=c(m,l,g,v,n[e+8],11,-2022574463),v=c(v,m,l,g,n[e+11],16,1839030562),g=c(g,v,m,l,n[e+14],23,-35309556),l=c(l,g,v,m,n[e+1],4,-1530992060),m=c(m,l,g,v,n[e+4],11,1272893353),v=c(v,m,l,g,n[e+7],16,-155497632),g=c(g,v,m,l,n[e+10],23,-1094730640),l=c(l,g,v,m,n[e+13],4,681279174),m=c(m,l,g,v,n[e],11,-358537222),v=c(v,m,l,g,n[e+3],16,-722521979),g=c(g,v,m,l,n[e+6],23,76029189),l=c(l,g,v,m,n[e+9],4,-640364487),m=c(m,l,g,v,n[e+12],11,-421815835),v=c(v,m,l,g,n[e+15],16,530742520),g=c(g,v,m,l,n[e+2],23,-995338651),l=f(l,g,v,m,n[e],6,-198630844),m=f(m,l,g,v,n[e+7],10,1126891415),v=f(v,m,l,g,n[e+14],15,-1416354905),g=f(g,v,m,l,n[e+5],21,-57434055),l=f(l,g,v,m,n[e+12],6,1700485571),m=f(m,l,g,v,n[e+3],10,-1894986606),v=f(v,m,l,g,n[e+10],15,-1051523),g=f(g,v,m,l,n[e+1],21,-2054922799),l=f(l,g,v,m,n[e+8],6,1873313359),m=f(m,l,g,v,n[e+15],10,-30611744),v=f(v,m,l,g,n[e+6],15,-1560198380),g=f(g,v,m,l,n[e+13],21,1309151649),l=f(l,g,v,m,n[e+4],6,-145523070),m=f(m,l,g,v,n[e+11],10,-1120210379),v=f(v,m,l,g,n[e+2],15,718787259),g=f(g,v,m,l,n[e+9],21,-343485551),l=t(l,i),g=t(g,a),v=t(v,h),m=t(m,d);return[l,g,v,m]}function a(n){var t,r="";for(t=0;t<32*n.length;t+=8)r+=String.fromCharCode(n[t>>5]>>>t%32&255);return r}function h(n){var t,r=[];for(r[(n.length>>2)-1]=void 0,t=0;t<r.length;t+=1)r[t]=0;for(t=0;t<8*n.length;t+=8)r[t>>5]|=(255&n.charCodeAt(t/8))<<t%32;return r}function d(n){return a(i(h(n),8*n.length))}function l(n,t){var r,e,o=h(n),u=[],c=[];for(u[15]=c[15]=void 0,o.length>16&&(o=i(o,8*n.length)),r=0;16>r;r+=1)u[r]=909522486^o[r],c[r]=1549556828^o[r];return e=i(u.concat(h(t)),512+8*t.length),a(i(c.concat(e),640))}function g(n){var t,r,e="0123456789abcdef",o="";for(r=0;r<n.length;r+=1)t=n.charCodeAt(r),o+=e.charAt(t>>>4&15)+e.charAt(15&t);return o}function v(n){return unescape(encodeURIComponent(n))}function m(n){return d(v(n))}function p(n){return g(m(n))}function s(n,t){return l(v(n),v(t))}function C(n,t){return g(s(n,t))}function A(n,t,r){return t?r?s(t,n):C(t,n):r?m(n):p(n)}"function"==typeof define&&define.amd?define(function(){return A}):"object"==typeof module&&module.exports?module.exports=A:n.md5=A}(this);

if (lwsgs_user.substring(0, 1) == "$") {
	alert("lwsgs.js: lws generic sessions misconfigured and not providing vars");
}
function lwsgs_san(s)
{
	if (s.search("<") != -1)
		return "invalid string";
	
	return s;
}

function lwsgs_update()
{
	var en_login = 1, en_forgot = 1;
	
	if (document.getElementById('password').value.length &&
	    document.getElementById('password').value.length < 8)
		en_login = 0;
	
	if (!document.getElementById('username').value ||
	    !document.getElementById('password').value)
		en_login = 0;
	
	if (!document.getElementById('username').value ||
	     document.getElementById('password').value)
		en_forgot = 0;
	
	document.getElementById('login').disabled = !en_login;
	document.getElementById('forgot').disabled = !en_forgot;
	
	if (lwsgs_user)
		document.getElementById("curuser").innerHTML = lwsgs_san(lwsgs_user);

	if (lwsgs_user === "")
		document.getElementById("dlogin").style.display = "inline";
	else
		document.getElementById("dlogout").style.display = "inline";
 }

function lwsgs_open_registration()
{
	document.getElementById("dadmin").style.display = "none";
	document.getElementById("dlogin").style.display = "none";
	document.getElementById("dlogout").style.display = "none";
	document.getElementById("dchange").style.display = "none";
	document.getElementById("dregister").style.display = "inline";
}

function lwsgs_cancel_registration()
{
	document.getElementById("dadmin").style.display = "none";
	document.getElementById("dregister").style.display = "none";
	document.getElementById("dchange").style.display = "none";

	if (lwsgs_user === "")
		document.getElementById("dlogin").style.display = "inline";
	else
		document.getElementById("dlogout").style.display = "inline";
}

function lwsgs_select_change()
{
	document.getElementById("dlogin").style.display = "none";
	document.getElementById("dlogout").style.display = "none";
	document.getElementById("dregister").style.display = "none";
	if (lwsgs_auth & 2) {
		document.getElementById("dadmin").style.display = "inline";
		document.getElementById("dchange").style.display = "none";
	} else {
		document.getElementById("dadmin").style.display = "none";
		document.getElementById("dchange").style.display = "inline";
	}

	event.preventDefault()
}

var lwsgs_user_check = '0';
var lwsgs_email_check = '0';

function lwsgs_rupdate()
{
	var en_register = 1, en_forgot = 0, op;

	if (document.getElementById('rpassword').value ==
	    document.getElementById('password2').value) {
		if (document.getElementById('rpassword').value.length)
			document.getElementById('match').innerHTML = 
				"<b class=\"green\">\u2713</b>";
		else
			document.getElementById('match').innerHTML = "";
		document.getElementById('pw2').style = "";
	} else {
		if (document.getElementById('password2').value ||
		    document.getElementById('email').value) { // ie, he is filling in "register" path and cares
			document.getElementById('match').innerHTML =
				"<span class=\"bad\">\u2718 <b>Passwords do not match</b></span>";
		} else
			document.getElementById('match').innerHTML =
				"<span class=\"bad\">\u2718 Passwords do not match</span>";

		en_register = 0;
	}

	if (document.getElementById('rpassword').value.length &&
	    document.getElementById('rpassword').value.length < 8) {
		en_register = 0;
		document.getElementById('rpw1').innerHTML = "Need 8 chars";
	} else
		if (document.getElementById('rpassword').value.length)
			document.getElementById('rpw1').innerHTML = "<b class=\"green\">\u2713</b>";
		else
			document.getElementById('rpw1').innerHTML = "";

	if (!document.getElementById('rpassword').value ||
	    !document.getElementById('password2').value ||
	    !document.getElementById('rusername').value ||
	    !document.getElementById('email').value ||
	    lwsgs_email_check === '1'||
	    lwsgs_user_check === '1')
		en_register = 0;

	document.getElementById('register').disabled = !en_register;
	document.getElementById('rpassword').disabled = lwsgs_user_check === '1';
	document.getElementById('password2').disabled = lwsgs_user_check === '1';
	document.getElementById('email').disabled = lwsgs_user_check === '1';

	if (lwsgs_user_check === '0') {
		var uc = document.getElementById('uchk');

		if (uc) {
			if (document.getElementById('rusername').value)
				uc.innerHTML = "<b class=\"green\">\u2713</b>";
			else
				uc.innerHTML = "";
		}
	} else {
		if (document.getElementById('uchk'))
			ocument.getElementById('uchk').innerHTML = "<b class=\"red\">\u2718 Already registered</b>";
		en_forgot = 1;
	}

	if (lwsgs_email_check === '0') {
		var ec = document.getElementById('echk');

		if (ec) {
			if (document.getElementById('email').value)
				ec.innerHTML = "<b class=\"green\">\u2713</b>";
			else
				ec.innerHTML = "";
		}
	} else {
		if (document.getElementById('echk'))
			document.getElementById('echk').innerHTML = "<b class=\"red\">\u2718 Already registered</b>";
		en_forgot = 1;
	}

	if (en_forgot)
		document.getElementById('rforgot').style.display = "inline";
	else
		document.getElementById('rforgot').style.display = "none";

	if (lwsgs_user_check === '1')
		op = '0.5';
	else
		op = '1.0';
	document.getElementById('rpassword').style.opacity = op;
 	document.getElementById('password2').style.opacity = op;
	document.getElementById('email').style.opacity = op;
 }

function lwsgs_cupdate()
{
	var en_change = 1, en_forgot = 1, pwok = 1, op;
	
	if (lwsgs_auth & 8) {
		document.getElementById('ccurpw').style.display = "none";
		document.getElementById('ccurpw_name').style.display = "none";
	} else {
		if (!document.getElementById('ccurpw').value ||
		    document.getElementById('ccurpw').value.length < 8) {
			en_change = 0;
			pwok = 0;
			document.getElementById('cuchk').innerHTML = "<b class=\"red\">\u2718</b>";
		} else {
			en_forgot = 0;
			document.getElementById('cuchk').innerHTML = "";
		}
		document.getElementById('ccurpw').style.display = "inline";
		document.getElementById('ccurpw_name').style.display = "inline";
	}

	if (document.getElementById('cpassword').value ==
	    document.getElementById('cpassword2').value) {
		if (document.getElementById('cpassword').value.length)
			document.getElementById('cmatch').innerHTML = "<b class=\"green\">\u2713</b>";
		else
			document.getElementById('cmatch').innerHTML = "";
		document.getElementById('pw2').style = "";
	} else {
		if (document.getElementById('cpassword2').value //||
		    //document.getElementById('cemail').value
		) { // ie, he is filling in "register" path and cares
			document.getElementById('cmatch').innerHTML =
				"<span class=\"red\">\u2718 <b>Passwords do not match</b></span>";
		} else
			document.getElementById('cmatch').innerHTML = "<span class=\"red\">\u2718 Passwords do not match</span>";

		en_change = 0;
	}

	if (document.getElementById('cpassword').value.length &&
	    document.getElementById('cpassword').value.length < 8) {
		en_change = 0;
		document.getElementById('cpw1').innerHTML = "Need 8 chars";
	} else {
		var cpw = document.getElementById('cpw1');

		if (cpw) {
			if (document.getElementById('cpassword').value.length)
				cpw.innerHTML = "<b class=\"green\">\u2713</b>";
			else
				cpw.innerHTML = "";
		}
	}

	if (!document.getElementById('cpassword').value ||
	    !document.getElementById('cpassword2').value ||
	    pwok === 0)
		en_change = 0;
	
	if (document.getElementById('showdel').checked)
		document.getElementById('delete').style.display = "inline";
	else
		document.getElementById('delete').style.display = "none";

	document.getElementById('change').disabled = !en_change;
	document.getElementById('cpassword').disabled = pwok === 0;
	document.getElementById('cpassword2').disabled = pwok === 0;
	document.getElementById('showdel').disabled = pwok === 0;
	document.getElementById('delete').disabled = pwok === 0;
	//document.getElementById('cemail').disabled = pwok === 0;

	/*
	if (lwsgs_auth & 8) {
		document.getElementById('cemail').style.display = "none";
		document.getElementById('cemail_name').style.display = "none";
	} else {
		document.getElementById('cemail').style.display = "inline";
		document.getElementById('cemail_name').style.display = "inline";
		if (lwsgs_email_check === '0'  &&
		    document.getElementById('cemail').value != lwsgs_email) {
			if (document.getElementById('cemail').value)
				document.getElementById('cechk').innerHTML = "<b style=\"color:green\">\u2713</b>";
			else
				document.getElementById('cechk').innerHTML = "";
		} else {
			document.getElementById('cechk').innerHTML = "<b style=\"color:red\">\u2718 Already registered</b>";
			en_forgot = 1;
		}
	} */
	
	if (lwsgs_auth & 8)
		en_forgot = 0;

	if (en_forgot)
		document.getElementById('cforgot').style.display = "inline";
	else
		document.getElementById('cforgot').style.display = "none";

	if (pwok === 0)
		op = '0.5';
	else
		op = '1.0';
	document.getElementById('cpassword').style.opacity = op;
 	document.getElementById('cpassword2').style.opacity = op;
	// document.getElementById('cemail').style.opacity = op;
 }

function lwsgs_check_user()
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() { 
        if (xmlHttp.readyState === 4 && xmlHttp.status === 200) {
            lwsgs_user_check = xmlHttp.responseText;
	    lwsgs_rupdate();
        }
    }
    xmlHttp.open("GET", "lwsgs-check/username="+document.getElementById('rusername').value, true);
    xmlHttp.send(null);
}

function lwsgs_check_email(id)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() { 
        if (xmlHttp.readyState === 4 && xmlHttp.status === 200) {
            lwsgs_email_check = xmlHttp.responseText;
	    lwsgs_rupdate();
        }
    }
    xmlHttp.open("GET", "lwsgs-check/email="+document.getElementById(id).value, true);
    xmlHttp.send(null);
}

function rupdate_user()
{
	lwsgs_rupdate();
	lwsgs_check_user();
}

function rupdate_email()
{
	lwsgs_rupdate();
	lwsgs_check_email('email');
}

function cupdate_email()
{
	lwsgs_cupdate();
	lwsgs_check_email('cemail');
}


function lwsgs_initial()
{
	document.getElementById('lwsgs').innerHTML = lwsgs_html;

	if (lwsgs_user) {
		document.getElementById("curuser").innerHTML =
			"currently logged in as " + lwsgs_san(lwsgs_user) + "</br>";

		document.getElementById("ccuruser").innerHTML =
		  "<span class=\"gstitle\">Login settings for " +
		  lwsgs_san(lwsgs_user) + "</span></br>";
	}

	document.getElementById('username').oninput = lwsgs_update;
	document.getElementById('username').onchange = lwsgs_update;
	document.getElementById('password').oninput = lwsgs_update;
	document.getElementById('password').onchange = lwsgs_update;
	document.getElementById('doreg').onclick = lwsgs_open_registration;
	document.getElementById('clink').onclick = lwsgs_select_change;
	document.getElementById('cancel').onclick =lwsgs_cancel_registration;
	document.getElementById('cancel2').onclick =lwsgs_cancel_registration;
 	document.getElementById('rpassword').oninput = lwsgs_rupdate;
 	document.getElementById('password2').oninput = lwsgs_rupdate;
	document.getElementById('rusername').oninput = rupdate_user;
	document.getElementById('email').oninput  = rupdate_email;
	document.getElementById('ccurpw').oninput = lwsgs_cupdate;
	document.getElementById('cpassword').oninput = lwsgs_cupdate;
	document.getElementById('cpassword2').oninput = lwsgs_cupdate;
<!--	document.getElementById('cemail').oninput = cupdate_email;-->
	document.getElementById('showdel').onchange = lwsgs_cupdate;

	if (lwsgs_email)
		document.getElementById('grav').innerHTML =
			"<img class='av' " +
			"src=\"https://www.gravatar.com/avatar/" +
			md5(lwsgs_email) +
			"?d=identicon\">";
	//if (lwsgs_email)
		//document.getElementById('cemail').placeholder = lwsgs_email;
	document.getElementById('cusername').value = lwsgs_user;
	lwsgs_update();
	lwsgs_cupdate();
}

window.addEventListener("load", function() {
	lwsgs_initial();
	document.getElementById("nolog").style.display = !!lwsgs_user ? "none" : "inline-block";
	document.getElementById("logged").style.display = !lwsgs_user ? "none" : "inline-block";

	document.getElementById("msg").onkeyup = mupd;
	document.getElementById("msg").onchange = mupd;

	var ws;

	function mb_format(s)
	{
		var r = "", n, wos = 0;
		
		for (n = 0; n < s.length; n++) {
			if (s[n] == ' ')
				wos = 0;
			else {
				wos++;
				if (wos === 40) {
					wos = 0;
					r = r + ' ';
				}
			}
			if (s[n] == '<') {
				r = r + "&lt;";
				continue;
			}
			if (s[n] == '\n') {
				r = r + "<br>";
				continue;
			}
				
			r = r + s[n];
		}
		
		return r;
	}

	function add_div(n, m)
	{
		var q = document.getElementById(n);
		var d = new Date(m.time * 1000), s = d.toTimeString(), t;
		
		t = s.indexOf('(');
		if (t)
			s = s.substring(0, t);
		
		q.innerHTML = "<br><div class=\"group2\"><table class=\"fixed\"><tr><td>" +
			"<img class=\"av\" src=\"https://www.gravatar.com/avatar/" + md5(m.email) +
			"?d=identicon\"><br>" +
			"<b>" + lwsgs_san(m.username) + "</b><br>" +
			"<span class=\"small\">" + d.toDateString() +
			  "<br>" + s + "</span><br>" +
			"IP: " + lwsgs_san(m.ip) +
			"</td><td class=\"ava\"><span>" +
			mb_format(m.content) +
			"</span></td></tr></table></div><br>" + q.innerHTML;
	}

	function get_appropriate_ws_url()
	{
		var pcol;
		var u = document.URL;

		if (u.substring(0, 5) == "https") {
			pcol = "wss://";
			u = u.substr(8);
		} else {
			pcol = "ws://";
			if (u.substring(0, 4) == "http")
				u = u.substr(7);
		}
		u = u.split('/');

		return pcol + u[0] + "/xxx";
	}

	if (lwsgs_user) {

		ws = new WebSocket(get_appropriate_ws_url(),
					   "protocol-lws-messageboard");

		try {
			ws.onopen = function() {
				document.getElementById("debug").textContent = "ws opened";
			}
			ws.onmessage =function got_packet(msg) {
				add_div("messages", JSON.parse(msg.data));
			}
			ws.onclose = function(){
			}
		} catch(exception) {
			alert('<p>Error' + exception);  
		}
	}

	function mupd()
	{
		document.getElementById("send").disabled = !document.getElementById("msg").value;
	}
}, false);
