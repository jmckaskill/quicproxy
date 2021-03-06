#!/bin/sh

for f in `find BearSSL/src BearSSL/tools -type f -name '*.c'`
do
    echo "build \$obj/ext/${f}.o: extcc ext/${f}"
done

echo "build \$obj/bearssl.lib: lib \$"
for f in `find BearSSL/src -type f -name '*.c'`
do
    echo " \$obj/ext/${f}.o \$"
done
echo
echo

echo "build \$bin/brssl.exe: clink \$"
for f in `find BearSSL/tools -type f -name '*.c'`
do
    echo " \$obj/ext/${f}.o \$"
done
echo " \$obj/bearssl.lib \$"
echo
echo