mkdir -p build
cd build
cmake -G "MSYS Makefiles" -DCMAKE_INSTALL_PREFIX=C:/MinGW -DCMAKE_BUILD_TYPE=DEBUG ..
make
make install