#!/bin/bash

J=`basename $1`
PI=`cat /tmp/sai-ctest-$J.$SAI_INSTANCE_IDX`
kill $PI
exit 0
