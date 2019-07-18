#!/bin/bash

PROGRAMES="sm2keygen sm2enc sm2sign sm4_evp"
INC_DIR=$HOME/thirdparty/TASSL-master-install/include
INC_DIR2=$HOME/thirdparty/TASSL-1.1.1b/crypto/include/internal
LIB_DIR=$HOME/thirdparty/TASSL-master-install/lib

if [ $1"X" == "cleanX" ]; then
printf "cleaning the programe %s.....\n" $PROGRAMES
	rm -rf ${PROGRAMES} 
else
printf "compiling the programe.....\n"
gcc -ggdb3 -O0 -o sm2keygen sm2keygen.c -I${INC_DIR} -I${INC_DIR2}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2enc sm2enc.c -I${INC_DIR}   -I${INC_DIR2} ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2sign sm2sign.c -I${INC_DIR} -I${INC_DIR2} ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm4_evp sm4_evp.c -I${INC_DIR} -I${INC_DIR2} ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
fi
