#!/bin/bash
set -e
rm -rf build
mkdir build
cd build
cmake .. -DLWS_WITH_SPAWN=1
make -j4
./bin/lws-api-test-lws_spawn
./bin/lws-api-test-spawn
