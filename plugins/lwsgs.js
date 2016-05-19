var lwsgs_user = "$lwsgs_user";
var lwsgs_auth = "$lwsgs_auth";
var lwsgs_email = "$lwsgs_email";

//alert("lwsgs_user = " + lwsgs_user);

if (lwsgs_user.substring(0, 1) == "$") {
	alert("lwsgs.js: lws generic sessions misconfigured and not providing vars");
}
function san(s)
{
	if (s.search("<") != -1)
		return "invalid string";
	
	return s;
}

