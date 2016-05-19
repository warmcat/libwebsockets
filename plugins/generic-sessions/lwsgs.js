<!-- lwsgs rewrites the below $vars $v $v into the correct values on the fly -->

var lwsgs_user = "$lwsgs_user";
var lwsgs_auth = "$lwsgs_auth";
var lwsgs_email = "$lwsgs_email";

var lwsgs_html = '       <div id="dlogin" style="display:none"> \
        <form action="login" method="post"> \
         <input type="hidden" name="admin" value="needadmin/admin-login.html"> \
         <input type="hidden" name="good" value="index.html"> \
         <input type="hidden" name="bad" value="failed-login.html"> \
         <input type="hidden" name="forgot-good" value="sent-forgot-ok.html"> \
         <input type="hidden" name="forgot-bad" value="sent-forgot-fail.html">\
         <input type="hidden" name="forgot-post-good" value="post-forgot-ok.html">\
         <input type="hidden" name="forgot-post-bad" value="post-forgot-fail.html">\
	 <table style="vertical-align:top;text-align:right"\
          <tr>\
           <td>User Name\
            <input type="text" size="10" id="username" name="username" oninput="lwsgs_update()"></td>\
           <td>Password\
            <input type="password" id="password" size="10" name="password" oninput="lwsgs_update()" onchange="lwsgs_update()"><div id="pw1"></div></td>\
	     </tr><tr>\
	   <td colspan="2" style="text-align:center"><input type="submit" id="login" name="login" value="Login" style="margin: 4px; padding: 2px; font-weight=bold;">\
      &nbsp;<input type="submit" id="forgot" name="forgot" value="Forgot password" style="margin: 2px; padding: 2px">\
           &nbsp;<input type="button" onclick="lwsgs_open_registration()" value="Sign up" style="margin: 2px; padding: 2px"></td>\
          </tr>\
         </table>\
        </form>\
       </div>\
\
       <div id="dlogout" style="display:none;text-align:right">\
        <form action="logout" method="post" style="text-align:right">\
         <input type="hidden" name="good" value="index.html">\
         <table style="vertical-align:top;text-align:right">\
          <tr>\
 	   <td style="text-align:right"><a href="#" onclick="lwsgs_select_change(); event.preventDefault();"><span id="curuser"></span></a></td>\
           <td><input type="submit" name="logout" value="Logout" style="margin: 2px; padding: 2px"></td>\
          </tr>\
         </table>\
        </form></div>\
\
	<div id="dregister" style="display:none">\
	 <form action="login" method="post">\
	  <input type="hidden" name="admin" value="needadmin/admin-login.html">\
	  <input type="hidden" name="good" value="successful-login.html">\
	  <input type="hidden" name="bad" value="failed-login.html">\
	  <input type="hidden" name="reg-good" value="post-register-ok.html">\
	  <input type="hidden" name="reg-bad" value="post-register-fail.html">\
	  <input type="hidden" name="forgot-good" value="sent-forgot-ok.html">\
	  <input type="hidden" name="forgot-bad" value="sent-forgot-fail.html">\
	  <input type="hidden" name="forgot-post-good" value="post-forgot-ok.html">\
	  <input type="hidden" name="forgot-post-bad" value="post-forgot-fail.html">\
	  <table style="vertical-align:top;text-align:left">\
	     <tr>\
	      <td colspan=2 align=center>\
		<span id="curuser"></span>\
	<script>\
		if (lwsgs_user)\
			document.getElementById("curuser").innerHTML = "currently logged in as " + lwsgs_san(lwsgs_user) + "</br>";\
	</script>\
	       <b>Please enter your details to register</b>:\
	      </td>\
	     </tr>\
	    <tr><td align=right>\
	     User Name:</td>\
	     <td><input type="text" size="10" id="rusername" name="username" oninput="lwsgs_rupdate(); lwsgs_check_user();">&nbsp;<span id=uchk></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Password:</td>\
	     <td><input type="password" size="10" id="rpassword" name="password" oninput="lwsgs_rupdate()">&nbsp;<span id="rpw1"></span></td>\
	    </tr>\
	    <tr>\
	    </tr>\
	    <tr>\
	     <td align=right><span id="pw2">Password (again):</span></td>\
	     <td><input type="password" size="10" id="password2" name="password2" oninput="lwsgs_rupdate()">&nbsp;<span id="match"></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Email:</td>\
	     <td><input type="email" size="10" id="email" name="email"\
	          placeholder="me@example.com" oninput="lwsgs_rupdate(); lwsgs_check_email(\'email\')">&nbsp;\
	          <span id=echk></span></td>\
	    </tr>\
	    <tr>\
	     <td colspan=2 align=center>\
<input type="submit" id="register" name="register" value="Register" style="margin: 2px; padding: 2px">\
<input type="submit" id="rforgot" name="forgot" value="Forgot Password" style="margin: 2px; padding: 2px;display: none">\
<input type="button" id="cancel" name="cancel" value="Cancel" style="margin: 2px; padding: 2px;" onclick="lwsgs_cancel_registration()">\
	     </td>\
	    </tr>\
         </table>\
        </form>\
       </div>\
       \
       <div id="dchange" style="display:none">\
        <form action="change" method="post">\
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
         <table style="vertical-align:top;text-align:left">\
	     <tr>\
	      <td colspan=2 align=center>\
		<span id="ccuruser"></span>\
	<script>\
		if (lwsgs_user)\
			document.getElementById("ccuruser").innerHTML =\
			  "<span class=\"gstitle\">Login settings for " +\
			  lwsgs_san(lwsgs_user) + "</span></br>";\
	</script>\
	       <b>Please enter your details to change</b>:\
	      </td>\
	     </tr>\
	    <tr><td align=right id="ccurpw_name">\
	     Current Password:</td>\
	     <td><input type="password" size="10" id="ccurpw" name="curpw"\
	          oninput="lwsgs_cupdate();">&nbsp;<span id=cuchk></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right>Password:</td>\
	     <td><input type="password" size="10" id="cpassword" name="password"\
	          oninput="lwsgs_cupdate()">&nbsp;<span id="cpw1"></span></td>\
	    </tr>\
	    <tr>\
	     <td align=right><span id="pw2">Password (again)</span></td>\
	     <td><input type="password" size="10" id="cpassword2" name="password2"\
	          oninput="lwsgs_cupdate()">&nbsp;<span id="cmatch"></span></td>\
	    </tr>\
	<!-- not supported yet\
	    <tr>\
	     <td align=right id="cemail_name">Email:</td>\
	     <td><input type="email" size="10" id="cemail" name="email"\
	     	  placeholder="?" oninput="lwsgs_cupdate(); lwsgs_check_email(\'cemail\')">\
	     	  &nbsp;<span id=cechk></span></td>\
	    </tr> -->\
	    <tr>\
	     <td colspan=2 align=center>\
	      <input type="submit" id="change" name="change"\
	       value="Change" style="margin: 6px; padding: 6px">\
	      <input type="submit" id="cforgot" name="forgot"\
	       value="Forgot Password" style="margin: 6px; padding: 6px;display: none">\
	      <input type="button" id="cancel" name="cancel"\
	       value="Cancel" style="margin: 6px; padding: 6px;"\
	       onclick="lwsgs_cancel_registration()">\
	     </td>\
	    </tr>\
	    <tr>\
	     <td>\
	      <input type="checkbox" id="showdel" name="showdel"\
	       value="Show Delete Account button" onchange="lwsgs_cupdate();">\
	       </br>\
	      <input type="button" id="delete" name="delete"\
	       value="Delete Account" style="margin: 6px; padding: 6px;">\
	     </td>\
	    </tr>\
         </table>\
        </form>\
       </div>\
       \
       <div id="dadmin" style="display:none">\
         Admin settings TBD\
       </div>\
';

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
}

var lwsgs_user_check = '0';
var lwsgs_email_check = '0';

function lwsgs_rupdate()
{
	var en_register = 1, en_forgot = 0;

	if (document.getElementById('rpassword').value ==
	    document.getElementById('password2').value) {
		if (document.getElementById('rpassword').value.length)
			document.getElementById('match').innerHTML = 
				"<b style=\"color:green\">\u2713</b>";
		else
			document.getElementById('match').innerHTML = "";
		document.getElementById('pw2').style = "";
	} else {
		if (document.getElementById('password2').value ||
		    document.getElementById('email').value) { // ie, he is filling in "register" path and cares
			document.getElementById('match').innerHTML =
				"<span style=\"color: red\">\u2718 <b>Passwords do not match</b></span>";
		} else
			document.getElementById('match').innerHTML =
				"<span style=\"color: gray\">\u2718 Passwords do not match</span>";

		en_register = 0;
	}

	if (document.getElementById('rpassword').value.length &&
	    document.getElementById('rpassword').value.length < 8) {
		en_register = 0;
		document.getElementById('rpw1').innerHTML = "Need 8 chars";
	} else
		if (document.getElementById('rpassword').value.length)
			document.getElementById('rpw1').innerHTML = "<b style=\"color:green\">\u2713</b>";
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
		if (document.getElementById('rusername').value)
			document.getElementById('uchk').innerHTML = "<b style=\"color:green\">\u2713</b>";
		else
			document.getElementById('uchk').innerHTML = "";
	} else {
		document.getElementById('uchk').innerHTML = "<b style=\"color:red\">\u2718 Already registered</b>";
		en_forgot = 1;
	}

	if (lwsgs_email_check === '0') {
		if (document.getElementById('email').value)
			document.getElementById('echk').innerHTML = "<b style=\"color:green\">\u2713</b>";
		else
			document.getElementById('echk').innerHTML = "";
	} else {
		document.getElementById('echk').innerHTML = "<b style=\"color:red\">\u2718 Already registered</b>";
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
	var en_change = 1, en_forgot = 1, pwok = 1;
	
	if (lwsgs_auth & 8) {
		document.getElementById('ccurpw').style.display = "none";
		document.getElementById('ccurpw_name').style.display = "none";
	} else {
		if (!document.getElementById('ccurpw').value ||
		    document.getElementById('ccurpw').value.length < 8) {
			en_change = 0;
			pwok = 0;
			document.getElementById('cuchk').innerHTML = "<b style=\"color:redn\">\u2718</b>";
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
			document.getElementById('cmatch').innerHTML = "<b style=\"color:green\">\u2713</b>";
		else
			document.getElementById('cmatch').innerHTML = "";
		document.getElementById('pw2').style = "";
	} else {
		if (document.getElementById('cpassword2').value //||
		    //document.getElementById('cemail').value
		) { // ie, he is filling in "register" path and cares
			document.getElementById('cmatch').innerHTML =
				"<span style=\"color: red\">\u2718 <b>Passwords do not match</b></span>";
		} else
			document.getElementById('cmatch').innerHTML = "<span style=\"color: gray\">\u2718 Passwords do not match</span>";

		en_change = 0;
	}

	if (document.getElementById('cpassword').value.length &&
	    document.getElementById('cpassword').value.length < 8) {
		en_change = 0;
		document.getElementById('cpw1').innerHTML = "Need 8 chars";
	} else
		if (document.getElementById('cpassword').value.length)
			document.getElementById('cpw1').innerHTML = "<b style=\"color:green\">\u2713</b>";
		else
			document.getElementById('cpw1').innerHTML = "";

	if (!document.getElementById('cpassword').value ||
	    !document.getElementById('cpassword2').value ||
	    pwok == 0)
		en_change = 0;

	document.getElementById('change').disabled = !en_change;
	document.getElementById('cpassword').disabled = pwok === 0;
	document.getElementById('cpassword2').disabled = pwok === 0;
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

	if (pwok == 0)
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
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
            lwsgs_user_check = xmlHttp.responseText;
	    lwsgs_rupdate();
        }
    }
    xmlHttp.open("GET", "check?username="+document.getElementById('rusername').value, true);
    xmlHttp.send(null);
}

function lwsgs_check_email(id)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() { 
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
            lwsgs_email_check = xmlHttp.responseText;
	    lwsgs_rupdate();
        }
    }
    xmlHttp.open("GET", "check?email="+document.getElementById(id).value, true);
    xmlHttp.send(null);
}

function lwsgs_initial()
{
	document.getElementById('lwsgs').innerHTML = lwsgs_html;
	//if (lwsgs_email)
		//document.getElementById('cemail').placeholder = lwsgs_email;
	document.getElementById('cusername').value = lwsgs_user;
	lwsgs_update();
	lwsgs_cupdate();
}
