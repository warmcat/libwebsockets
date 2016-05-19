<!-- lwsgs rewrites the below $vars $v $v into the correct values on the fly -->

var lwsgs_user = "$lwsgs_user";
var lwsgs_auth = "$lwsgs_auth";
var lwsgs_email = "$lwsgs_email";

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
	//if (lwsgs_email)
		//document.getElementById('cemail').placeholder = lwsgs_email;
		document.getElementById('cusername').value = lwsgs_user;
	lwsgs_update();
	lwsgs_cupdate();
}
