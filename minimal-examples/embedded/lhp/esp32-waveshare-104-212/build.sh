#!/bin/sh

USBPORT="/dev/serial/by-path/pci-0000:00:14.0-usb-0:8.4.2.3.4:1.0-port0"

idf.py build
if [ $? -ne 0 ] ; then
	exit 1;
fi

#
#      (no arg) flash from scratch
# u    Upload to repo and reboot
# f    Force update into both OTA and reboot
#

if [ -z "$1" ] ; then
	idf.py -p $USBPORT build flash
fi

if [ "$1" == "p" ] ; then
	idf.py -p $USBPORT partition-table-flash
fi


if [ "$1" == "u" ] ; then
	../../../../contrib/lws_ota-manifest.sh  \
		build/lws-minimal-esp32.bin \
		../../../../libwebsockets.org-ota-v1.private.jwk \
		"libwebsockets.org:/var/www/libwebsockets.org/firmware/examples/"
fi

if [ "$1" == "f" ] ; then
	parttool.py --baud 921600 --port $USBPORT -f partitions.csv write_partition --partition-name=ota_0 --input build/lws-minimal-esp32.bin
	parttool.py --baud 921600 --port $USBPORT -f partitions.csv write_partition --partition-name=ota_1 --input build/lws-minimal-esp32.bin
fi

idf.py -p $USBPORT monitor

