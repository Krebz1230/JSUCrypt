#!/bin/bash  -x

pushd .
cd `dirname tests/test.sh`

files="
../dist/lib/jsbn/jsbn.js
../dist/lib/jsbn/jsbn2.js
../dist/lib/JSUCrypt.js
../dist/lib/helpers.js
../dist/lib/hash.js
../dist/lib/pad.js
../dist/lib/keys.js
../dist/lib/cipher.js
../dist/lib/signature.js
../dist/lib/ka.js
../dist/lib/sha1.js
../dist/lib/sha256.js
../dist/lib/ripemd160.js
../dist/lib/ecfp.js
../dist/lib/des.js
../dist/lib/rsa.js
../dist/lib/ecdsa.js
../dist/lib/ecdh.js
"
#../dist/aes.js
#../dist/md5.js

#RHINO="rhino-debugger"
RHINO="rhino"
${RHINO}  -strict  `for x in $files; do echo -f $x; done` test.js


popd 