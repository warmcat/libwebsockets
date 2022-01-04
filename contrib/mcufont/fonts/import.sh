#!/bin/sh

PIXEL_SIZES="10 12 14 16 20 24 32"
RANGES="0-255 0x2010-0x2015"
MCUFONT=../../../build/bin/lws-mcufont-encoder

for i in $PIXEL_SIZES ; do
	$MCUFONT import_ttf $1 $i
	DAT=`echo $1 | sed 's/\.ttf$//'`$i.dat
	$MCUFONT filter $DAT $RANGES
	$MCUFONT rlefont_optimize $DAT 50
        $MCUFONT rlefont_export $DAT 	
done

