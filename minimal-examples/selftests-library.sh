
if [ -z "$1" -o -z "$2" ] ; then
	echo "required args missing"
	exit 1
fi

IDX=$3
TOT=$4
MYTEST=`echo $0 | sed "s/\/[^\/]*\$//g" |sed "s/.*\///g"`
mkdir -p $2/$MYTEST
rm -f $2/$MYTEST/*.log $2/$MYTEST/*.result
FAILS=0
WHICH=$IDX
SPID=
SCRIPT_DIR=`dirname $0`
SCRIPT_DIR=`readlink -f $SCRIPT_DIR`
LOGPATH=$2

feedback() {
	if [ "$2" != "0" ] ; then
		FAILS=$(( $FAILS + 1 ))
		echo -n -e "\e[31m"
	fi
	T="  ---  killed  ---  "
	if [ ! -z "`cat $LOGPATH/$MYTEST/$3.time`" ] ; then
		T="`cat $LOGPATH/$MYTEST/$3.time | grep real | sed "s/.*\ //g"`"
		T="$T `cat $LOGPATH/$MYTEST/$3.time | grep user | sed "s/.*\ //g"`"
		T="$T `cat $LOGPATH/$MYTEST/$3.time | grep sys | sed "s/.*\ //g"`"
	fi
	printf "%-35s [ %3s/%3s ]: %3s : %8s : %s\n" $1 $WHICH $TOT $2 "$T" $3
	if [ "$2" != "0" ] ; then
		echo -n -e "\e[0m"
	fi
	WHICH=$(( $WHICH + 1))
}

spawn() {
	if [ ! -z "$1" ] ; then
		if [ `ps $1 | wc -l` -eq 2 ]; then
#			echo "prerequisite still up"
			return 0
		fi
	fi

	QQ=`pwd`
	cd $SCRIPT_DIR
	cd $2
	$3 $4 $5 > $LOGPATH/$MYTEST/serverside.log 2> $LOGPATH/$MYTEST/serverside.log &
	SPID=$!
	cd $QQ
	sleep 0.5s
#	echo "launched prerequisite $SPID"
}

dotest() {
	T=$3
	(
		{
			/usr/bin/time -p $1/lws-$MYTEST $4 $5 $6 $7 > $2/$MYTEST/$T.log 2> $2/$MYTEST/$T.log ;
			echo $? > $2/$MYTEST/$T.result
		} 2> $2/$MYTEST/$T.time >/dev/null
	) >/dev/null 2> /dev/null &
	W=$!
	WT=0
	while [ $WT -le 220 ] ; do
		kill -0 $W 2>/dev/null
		if [ $? -ne 0 ] ; then
			WT=10000
		else
			if [ $WT -ge 200 ] ; then
				WT=10000
				kill $W 2>/dev/null
				wait $W 2>/dev/null
			fi
		fi
		sleep 0.1s
		WT=$(( $WT + 1 ))
	done

	R=254
	if [ -e $2/$MYTEST/$T.result ] ; then
		R=`cat $2/$MYTEST/$T.result`
		cat $2/$MYTEST/$T.log | tail -n 3 > $2/$MYTEST/$T.time
		if [ $R -ne 0 ] ; then
			pwd
			echo
			cat $2/$MYTEST/$T.log
			echo
		fi
	fi

	feedback $MYTEST $R $T
}

