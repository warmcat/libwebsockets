#!/bin/bash
#
# attack the test server and try to make it fall over
#
SERVER=127.0.0.1
PORT=7681
LOG=/tmp/lwslog

A=`which libwebsockets-test-server`
INSTALLED=`dirname $A`

CPID=
LEN=0

function check {
	kill -0 $CPID
	if [ $? -ne 0 ] ; then
		echo "(killed it) *******"
		exit 1
	fi
	dd if=$LOG bs=1 skip=$LEN 2>/dev/null

	if [ "$1" = "default" ] ; then
		diff /tmp/lwscap $INSTALLED/../share/libwebsockets-test-server/test.html > /dev/null
		if [ $? -ne 0 ] ; then
			echo "FAIL: got something other than test.html back"
			exit 1
		fi
	fi
	if [ "$1" = "defaultplusforbidden" ] ; then
	cat $INSTALLED/../share/libwebsockets-test-server/test.html > /tmp/plusforb
	echo -e -n "HTTP/1.0 403 Forbidden\x0d\x0acontent-type: text/html\x0d\x0acontent-length: 38\x0d\x0a\x0d\x0a<html><body><h1>403</h1></body></html>" >> /tmp/plusforb
		diff /tmp/lwscap /tmp/plusforb > /dev/null
		if [ $? -ne 0 ] ; then
			cat $INSTALLED/../share/libwebsockets-test-server/test.html > /tmp/plusforb

			echo -e -n "HTTP/1.1 403 Forbidden\x0d\x0acontent-type: text/html\x0d\x0acontent-length: 38\x0d\x0a\x0d\x0a<html><body><h1>403</h1></body></html>" >> /tmp/plusforb
			diff /tmp/lwscap /tmp/plusforb > /dev/null
			if [ $? -ne 0 ] ; then

				echo "FAIL: got something other than test.html + forbidden back"
				exit 1
			fi
		fi
	fi

	if [ "$1" = "forbidden" ] ; then
		if [ -z "`grep '<h1>403</h1>' /tmp/lwscap`" ] ; then
			echo "FAIL: should have told forbidden (test server has no dirs)"
			exit 1
		fi
	fi

	if [ "$1" = "rejected" ] ; then
		if [ -z "`grep '<h1>406</h1>' /tmp/lwscap`" ] ; then
			echo "FAIL: should have told forbidden (test server has no dirs)"
			exit 1
		fi
	fi


	if [ "$1" = "media" ] ; then
		if [ -z "`grep '<h1>415</h1>' /tmp/lwscap`" ] ; then
			echo "FAIL: should have told unknown media type"
			exit 1
		fi
	fi

	if [ "$1" == "0" ] ; then
		a="`dd if=$LOG bs=1 skip=$LEN 2>/dev/null |grep "get\ \ =" | tr -s ' ' | cut -d' ' -f4-`"
		if [ "$a" != "$2" ] ; then
			echo "URL path '$a' not $2"
			exit 1
		fi
	fi

	if [ "$1" == "1" ] ; then
		a="`dd if=$LOG bs=1 skip=$LEN 2>/dev/null |grep URI\ Arg\ 1\: | tr -s ' ' | cut -d' ' -f5-`"
		if [ "$a" != "$2" ] ; then
			echo "Arg 1 '$a' not $2"
			exit 1
		fi
	fi

	if [ "$1" == "2" ] ; then
		a="`dd if=$LOG bs=1 skip=$LEN 2>/dev/null |grep URI\ Arg\ 2\: | tr -s ' ' | cut -d' ' -f5-`"
		if [ "$a" != "$2" ] ; then
			echo "Arg 2 '$a' not $2"
			exit 1
		fi
	fi
	if [ "$1" == "3" ] ; then
		a="`dd if=$LOG bs=1 skip=$LEN 2>/dev/null |grep URI\ Arg\ 3\: | tr -s ' ' | cut -d' ' -f5-`"
		if [ "$a" != "$2" ] ; then
			echo "Arg 3 '$a' not $2"
			exit 1
		fi
	fi

	if [ -z "$1" ] ; then
		LEN=`stat $LOG -c %s`
	fi
}


rm -rf $LOG
killall libwebsockets-test-server 2>/dev/null
libwebsockets-test-server -d127 2>> $LOG &
CPID=$!

echo "Started server on PID $CPID"

while [ -z "`grep ort\ 7681 $LOG`" ] ; do
	sleep 0.5s
done
check

echo
echo "---- /cgi-bin/settingsjs?UPDATE_SETTINGS=1&Root_Channels_1_Channel_name_http_post=%3F&Root_Channels_1_Channel_location_http_post=%3F"
rm -f /tmp/lwscap
echo -n -e "GET /cgi-bin/settingsjs?UPDATE_SETTINGS=1&Root_Channels_1_Channel_name_http_post=%3F&Root_Channels_1_Channel_location_http_post=%3F HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check 1 "UPDATE_SETTINGS=1"
check 2 "Root_Channels_1_Channel_name_http_post=?"
check 3 "Root_Channels_1_Channel_location_http_post=?"
check

echo
echo "---- ? processing (/cgi-bin/settings.js?key1=value1)"
rm -f /tmp/lwscap
echo -n -e "GET /cgi-bin/settings.js?key1=value1 HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check 1 "key1=value1"
check

echo
echo "---- ? processing (/t%3dest?key1%3d2=value1)"
rm -f /tmp/lwscap
echo -n -e "GET /t%3dest?key1%3d2=value1 HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check 0 "/t=est"
check 1 "key1_2=value1"
check

echo
echo "---- ? processing (%2f%2e%2e%2f%2e./test.html?arg=1)"
rm -f /tmp/lwscap
echo  -n -e "GET %2f%2e%2e%2f%2e./test.html?arg=1 HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check 1 "arg=1"
check

echo
echo "---- ? processing (%2f%2e%2e%2f%2e./test.html?arg=/../.)"
rm -f /tmp/lwscap
echo -n -e "GET %2f%2e%2e%2f%2e./test.html?arg=/../. HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check 1 "arg=/../."
check

echo
echo "---- spam enough crap to not be GET"
echo "not GET" | nc $SERVER $PORT
check

echo
echo "---- spam more than the name buffer of crap"
dd if=/dev/urandom bs=1 count=80 2>/dev/null | nc -i1s $SERVER $PORT
check

echo
echo "---- spam 10MB of crap"
dd if=/dev/urandom bs=1 count=655360 | nc -i1s $SERVER $PORT
check

echo
echo "---- malformed URI"
echo "GET nonsense................................................................................................................" \
	| nc -i1s $SERVER $PORT
check

echo
echo "---- missing URI"
echo -n -e "GET HTTP/1.0\x0d\x0a\x0d\x0a" | nc -i1s $SERVER $PORT >/tmp/lwscap
check

echo
echo "---- repeated method"
echo -n -e "GET blah HTTP/1.0\x0d\x0aGET blah HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT >/tmp/lwscap 
check

echo
echo "---- crazy header name part"
echo -n -e "GET blah HTTP/1.0\x0d\x0a................................................................................................................" \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 | nc -i1s $SERVER $PORT
check

echo
echo "---- excessive uri content"
echo -n -e "GET ................................................................................................................" \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 | nc -i1s $SERVER $PORT
check

echo
echo "---- good request but http payload coming too (test.html served then forbidden)"
echo -n -e "GET /test.html HTTP/1.1\x0d\x0a\x0d\x0aILLEGAL-PAYLOAD........................................" \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
 	"......................................................................................................................." \
	 | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check defaultplusforbidden
check

echo
echo "---- nonexistent file"
rm -f /tmp/lwscap
echo -n -e "GET /nope HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check media
check

echo
echo "---- relative uri path"
rm -f /tmp/lwscap
echo -n -e "GET nope HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check forbidden
check

echo
echo "---- directory attack 1 (/../../../../etc/passwd should be /etc/passswd)"
rm -f /tmp/lwscap
echo -n -e "GET /../../../../etc/passwd HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check rejected
check

echo
echo "---- directory attack 2 (/../ should be /)"
rm -f /tmp/lwscap
echo -e -n "GET /../ HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check default
check

echo
echo "---- directory attack 3 (/./ should be /)"
rm -f /tmp/lwscap
echo -e -n "GET /./ HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check default
check

echo
echo "---- directory attack 4 (/blah/.. should be /)"
rm -f /tmp/lwscap
echo -e -n "GET /blah/.. HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check default
check

echo
echo "---- directory attack 5 (/blah/../ should be /)"
rm -f /tmp/lwscap
echo -e -n "GET /blah/../ HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check default
check

echo
echo "---- directory attack 6 (/blah/../. should be /)"
rm -f /tmp/lwscap
echo -e -n "GET /blah/../. HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check default
check

echo
echo "---- directory attack 7 (/%2e%2e%2f../../../etc/passwd should be /etc/passswd)"
rm -f /tmp/lwscap
echo -e -n "GET /%2e%2e%2f../../../etc/passwd HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check rejected
check

echo
echo "---- directory attack 8 (%2f%2e%2e%2f%2e./.%2e/.%2e%2fetc/passwd should be /etc/passswd)"
rm -f /tmp/lwscap
echo -e -n "GET %2f%2e%2e%2f%2e./.%2e/.%2e%2fetc/passwd HTTP/1.0\x0d\x0a\x0d\x0a" | nc $SERVER $PORT | sed '1,/^\r$/d'> /tmp/lwscap
check rejected
check

echo
echo "---- http/1.1 pipelining"
rm -f /tmp/lwscap
wget -O/tmp/lwsdump http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html http://localhost:7681/test.html 2>&1 | grep "Downloaded: 8 files" > /tmp/lwscap
good=`cat $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html $INSTALLED/../share/libwebsockets-test-server/test.html | md5sum | cut -d' ' -f1`
if [ "$good" != "`md5sum /tmp/lwsdump | cut -d' ' -f 1`" ] ; then
	echo "FAIL: mismatched content good=$good received=`md5sum /tmp/lwsdump`"
	exit 1
fi

echo
echo "---- mass testing uri variations"

rm -f /tmp/results

for i in \
/..../ \
/.../. \
/...// \
/.../a \
/.../w \
/.../? \
/.../% \
/../.. \
/.././ \
/../.a \
/../.w \
/../.. \
/../.% \
/..//. \
/../// \
/..//a \
/..//w \
/..//? \
/..//% \
/../a. \
/../a/ \
/../aa \
/../aw \
/../a? \
/../a% \
/../w. \
/../w/ \
/../wa \
/../ww \
/../w? \
/../w% \
/../?. \
/../?/ \
/../?a \
/../?w \
/../?? \
/../?% \
/../%. \
/../%/ \
/../%a \
/../%w \
/../%? \
/../%% \
/./... \
/./../ \
/./..a \
/./..w \
/./..? \
/./..% \
/.//.. \
/.a../ \
/.a/.. \
/.w../ \
/.w/.. \
/.?../ \
/../.. \
/.%../ \
/.%/.. \
//.... \
//.../ \
//...a \
//...w \
//...? \
//...% \
//../. \
//..// \
//../a \
//../w \
//../? \
//../% \
//..a. \
//..a/ \
//..aa \
//..aw \
//..a? \
//..a% \
//..w. \
//..w/ \
//..wa \
//..ww \
//..w? \
//..w% \
//..?. \
//..?/ \
//..?a \
//..?w \
//..?? \
//..?% \
//..%. \
//..%/ \
//..%a \
//..%w \
//..%? \
//..%% \
//./.. \
///... \
///../ \
///..a \
///..w \
///..? \
///..% \
////.. \
//a../ \
//a/.. \
//w../ \
//w/.. \
//?../ \
//?/.. \
//%../ \
//%/.. \
/a.../ \
/a../. \
/a..// \
/a../a \
/a../w \
/a../? \
/a../% \
/a./.. \
/a/... \
/a/../ \
/a/..a \
/a/..w \
/a/..? \
/a/..% \
/a//.. \
/aa../ \
/aa/.. \
/aw../ \
/aw/.. \
/a?../ \
/a?/.. \
/a%../ \
/a%/.. \
/w.../ \
/w../. \
/w..// \
/w../a \
/w../w \
/w../? \
/w../% \
/w./.. \
/w/... \
/w/../ \
/w/..a \
/w/..w \
/w/..? \
/w/..% \
/w//.. \
/wa../ \
/wa/.. \
/ww../ \
/ww/.. \
/w?../ \
/w?/.. \
/w%../ \
/w%/.. \
/?.../ \
/?../. \
/?..// \
/?../a \
/?../w \
/?../? \
/?../% \
/?./.. \
/?/... \
/?/../ \
/?/..a \
/?/..w \
/?/..? \
/?/..% \
/?//.. \
/?a../ \
/?a/.. \
/?w../ \
/?w/.. \
/??../ \
/??/.. \
/?%../ \
/?%/.. \
/%.../ \
/%../. \
/%..// \
/%../a \
/%../w \
/%../? \
/%../% \
/%./.. \
/%/... \
/%/../ \
/%/..a \
/%/..w \
/%/..? \
/%/..% \
/%//.. \
/%a../ \
/%a/.. \
/%w../ \
/%w/.. \
/%?../ \
/%?/.. \
/%%../ \
/%%/.. \
/a/w/../a \
/path/to/dir/../other/dir \
; do

R=`rm -f /tmp/lwscap ; echo -n -e "GET $i HTTP/1.0\r\n\r\n" | nc localhost 7681 2>/dev/null >/tmp/lwscap; head -n1 /tmp/lwscap| cut -d' ' -f2`

cat /tmp/lwscap | head -n1
echo ==== $R


if [ "$R" != "403" ]; then
	U=`cat $LOG | grep lws_http_serve | tail -n 1 | cut -d':' -f3 | cut -d' ' -f2`
	echo $U
	echo "- \"$i\" -> $R \"$U\"" >>/tmp/results
else
	echo "- \"$i\" -> $R" >>/tmp/results
fi
done

cat <<EOF >/tmp/lwsresult1
- "/..../" -> 406 "/..../"
- "/.../." -> 406 "/.../"
- "/...//" -> 406 "/.../"
- "/.../a" -> 406 "/.../a"
- "/.../w" -> 406 "/.../w"
- "/.../?" -> 406 "/.../"
- "/.../%" -> 403
- "/../.." -> 200 "/"
- "/.././" -> 200 "/"
- "/../.a" -> 415 "/.a"
- "/../.w" -> 415 "/.w"
- "/../.." -> 200 "/"
- "/../.%" -> 403
- "/..//." -> 200 "/"
- "/..///" -> 200 "/"
- "/..//a" -> 415 "/a"
- "/..//w" -> 415 "/w"
- "/..//1" -> 415 "/1"
- "/..//%" -> 403
- "/../a." -> 415 "/a."
- "/../a/" -> 406 "/a/"
- "/../aa" -> 415 "/aa"
- "/../aw" -> 415 "/aw"
- "/../a?" -> 415 "/a"
- "/../a%" -> 403
- "/../w." -> 415 "/w."
- "/../w/" -> 406 "/w/"
- "/../wa" -> 415 "/wa"
- "/../ww" -> 415 "/ww"
- "/../w?" -> 415 "/w"
- "/../w%" -> 403
- "/../?." -> 200 "/"
- "/../?/" -> 200 "/"
- "/../?a" -> 200 "/"
- "/../?w" -> 200 "/"
- "/../??" -> 200 "/"
- "/../?%" -> 403
- "/../%." -> 403
- "/../%/" -> 403
- "/../%a" -> 403
- "/../%w" -> 403
- "/../%?" -> 403
- "/../%%" -> 403
- "/./..." -> 415 "/..."
- "/./../" -> 200 "/"
- "/./..a" -> 415 "/..a"
- "/./..w" -> 415 "/..w"
- "/./..?" -> 200 "/"
- "/./..%" -> 403
- "/.//.." -> 200 "/"
- "/.a../" -> 406 "/.a../"
- "/.a/.." -> 200 "/"
- "/.w../" -> 406 "/.w../"
- "/.w/.." -> 200 "/"
- "/.?../" -> 415 "/."
- "/../.." -> 200 "/"
- "/.%../" -> 403
- "/.%/.." -> 403
- "//...." -> 415 "/...."
- "//.../" -> 406 "/.../"
- "//...a" -> 415 "/...a"
- "//...w" -> 415 "/...w"
- "//...?" -> 415 "/..."
- "//...%" -> 403
- "//../." -> 200 "/"
- "//..//" -> 200 "/"
- "//../a" -> 415 "/a"
- "//../w" -> 415 "/w"
- "//../1" -> 415 "/1"
- "//../%" -> 403
- "//..a." -> 415 "/..a."
- "//..a/" -> 406 "/..a/"
- "//..aa" -> 415 "/..aa"
- "//..aw" -> 415 "/..aw"
- "//..a?" -> 415 "/..a"
- "//..a%" -> 403
- "//..w." -> 415 "/..w."
- "//..w/" -> 406 "/..w/"
- "//..wa" -> 415 "/..wa"
- "//..ww" -> 415 "/..ww"
- "//..w?" -> 415 "/..w"
- "//..w%" -> 403
- "//..?." -> 200 "/"
- "//..?/" -> 200 "/"
- "//..?a" -> 415 "/a"
- "//..?w" -> 415 "/w"
- "//..??" -> 200 "/"
- "//..?%" -> 403
- "//..%." -> 403
- "//..%/" -> 403
- "//..%a" -> 403
- "//..%w" -> 403
- "//..%?" -> 403
- "//..%%" -> 403
- "//./.." -> 200 "/"
- "///..." -> 415 "/..."
- "///../" -> 200 "/"
- "///..a" -> 415 "/..a"
- "///..w" -> 415 "/..w"
- "///..?" -> 200 "/"
- "///..%" -> 403
- "////.." -> 200 "/"
- "//a../" -> 406 "/a../"
- "//a/.." -> 200 "/"
- "//w../" -> 406 "/w../"
- "//w/.." -> 200 "/"
- "//?../" -> 200 "/"
- "//?/.." -> 200 "/"
- "//%../" -> 403
- "//%/.." -> 403
- "/a.../" -> 406 "/a.../"
- "/a../." -> 406 "/a../"
- "/a..//" -> 406 "/a../"
- "/a../a" -> 406 "/a../a"
- "/a../w" -> 406 "/a../w"
- "/a../?" -> 406 "/a../"
- "/a../%" -> 403
- "/a./.." -> 200 "/"
- "/a/..." -> 406 "/a/..."
- "/a/../" -> 200 "/"
- "/a/..a" -> 406 "/a/..a"
- "/a/..w" -> 406 "/a/..w"
- "/a/..?" -> 200 "/"
- "/a/..%" -> 403
- "/a//.." -> 200 "/"
- "/aa../" -> 406 "/aa../"
- "/aa/.." -> 200 "/"
- "/aw../" -> 406 "/aw../"
- "/aw/.." -> 200 "/"
- "/a?../" -> 415 "/a"
- "/a?/.." -> 415 "/a"
- "/a%../" -> 403
- "/a%/.." -> 403
- "/w.../" -> 406 "/w.../"
- "/w../." -> 406 "/w../"
- "/w..//" -> 406 "/w../"
- "/w../a" -> 406 "/w../a"
- "/w../w" -> 406 "/w../w"
- "/w../?" -> 406 "/w../"
- "/w../%" -> 403
- "/w./.." -> 200 "/"
- "/w/..." -> 406 "/w/..."
- "/w/../" -> 200 "/"
- "/w/..a" -> 406 "/w/..a"
- "/w/..w" -> 406 "/w/..w"
- "/w/..?" -> 200 "/"
- "/w/..%" -> 403
- "/w//.." -> 200 "/"
- "/wa../" -> 406 "/wa../"
- "/wa/.." -> 200 "/"
- "/ww../" -> 406 "/ww../"
- "/ww/.." -> 200 "/"
- "/w?../" -> 415 "/w"
- "/w?/.." -> 415 "/w"
- "/w%../" -> 403
- "/w%/.." -> 403
- "/?.../" -> 200 "/"
- "/?../." -> 200 "/"
- "/?..//" -> 200 "/"
- "/?../a" -> 200 "/"
- "/?../w" -> 200 "/"
- "/?../?" -> 200 "/"
- "/?../%" -> 403
- "/?./.." -> 200 "/"
- "/?/..." -> 200 "/"
- "/?/../" -> 200 "/"
- "/?/..a" -> 200 "/"
- "/?/..w" -> 200 "/"
- "/?/..?" -> 200 "/"
- "/?/..%" -> 403
- "/?//.." -> 200 "/"
- "/?a../" -> 200 "/"
- "/?a/.." -> 200 "/"
- "/?w../" -> 200 "/"
- "/?w/.." -> 200 "/"
- "/??../" -> 200 "/"
- "/??/.." -> 200 "/"
- "/?%../" -> 403
- "/?%/.." -> 403
- "/%.../" -> 403
- "/%../." -> 403
- "/%..//" -> 403
- "/%../a" -> 403
- "/%../w" -> 403
- "/%../?" -> 403
- "/%../%" -> 403
- "/%./.." -> 403
- "/%/..." -> 403
- "/%/../" -> 403
- "/%/..a" -> 403
- "/%/..w" -> 403
- "/%/..?" -> 403
- "/%/..%" -> 403
- "/%//.." -> 403
- "/%a../" -> 403
- "/%a/.." -> 403
- "/%w../" -> 403
- "/%w/.." -> 403
- "/%?../" -> 403
- "/%?/.." -> 403
- "/%%../" -> 403
- "/%%/.." -> 403
- "/a/w/../a" -> 406 "/a/a"
- "/path/to/dir/../other/dir" -> 406 "/path/to/other/dir"
EOF

if [ "`md5sum /tmp/results | cut -d' ' -f 1`" != "`md5sum /tmp/lwsresult1 | cut -d' ' -f1`" ] ; then
	echo "Differences..."
	diff -urN /tmp/results /tmp/lwsresult1
	exit 1
else
	echo "OK"
fi


echo
echo "--- survived OK ---"
kill -2 $CPID

exit 0


