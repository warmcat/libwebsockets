#!/bin/bash

J=`basename $1`
sh -c "echo $$ > /tmp/sai-ctest-$J.$SAI_INSTANCE_IDX ; exec $1 $2 $3 $4 $5 $6 $7 $8 $9 2>/dev/null 1>/dev/null 0</dev/null" &
sleep 0.2
exit 0

