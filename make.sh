rm -rf build
mkdir build
cd build
cmake .. -DLWS_WITH_MINIMAL_EXAMPLES=1
make
