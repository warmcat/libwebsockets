#!/bin/bash

if [ "$COVERITY_SCAN_BRANCH" == 1 ]; then exit; fi

if [ "$TRAVIS_OS_NAME" == "linux" ];
then
	sudo apt-get update -qq

	if [ "$LWS_METHOD" == "lwsws" ];
	then
		sudo apt-get install -y -qq realpath;
		sudo apt-get remove python-six
		sudo pip install six>=1.9
		sudo pip install Twisted==16.0.0
		sudo pip install pyopenssl>=0.14
		sudo pip install autobahntestsuite
	fi

	if [ "$LWS_METHOD" == "libev" ];
	then
		sudo apt-get install -y -qq libev-dev;
	fi

	if [ "$LWS_METHOD" == "libuv" -o "$LWS_METHOD" == "lwsws" ];
	then
		sudo apt-get install -y -qq libuv-dev;
#libuv1 libuv1-dev;
	fi

fi

if [ "$TRAVIS_OS_NAME" == "osx" ];
then
	if [ "$LWS_METHOD" == "libev" ];
	then
		brew update;
		brew install libev;
	fi

	if [ "$LWS_METHOD" == "libuv" -o "$LWS_METHOD" == "lwsws" ];
	then
		brew update;
		brew install libuv;
	fi

fi

	
