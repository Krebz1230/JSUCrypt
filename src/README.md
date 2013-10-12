

## Introduction

A tiny, unified and simple crypto library.

The main goals of the library are:

     - provide an unified APIs for various cryptography operations
     - easy to extends
     - easy to reduce
     - easy to use for prototyping and research.
    
This beta release of UCrypt does not feature performance at main goal, but it's not a naive implementation....


## About types

The APIs documentation use the follwing type convention:

 - 'byte[]' a array of number, with all element comprised between 0 and 256

 - 'anyBN' type for parameters means any type convertable in BigNumber with 
 the 'anyToBigInteger' function. For now anyBN can be:

     - {number}     int number              eg: 2
     - {string}     literal HexString       eg: "abcd"  (no leading Ox)
     - {byte[]}     array of byte           eg: [ 42, 12, 128 ]
     - {BigInteger} 


 - 'anyBA' type for parameters means any type convertable in byte array with 
 the 'anyToByteArray' function. For now anyBA can be:

     - {number}     int number              eg: 2
     - {string}     literal HexString       eg: "abcd"  (no leading Ox), (ie 0xab, 0xcd)
     - {byte[]}     array of byte           eg: [ 42, 12, 128 ]

## Use it

Read this doc

Insert something like that in your html page:

        <script type="text/javascript" src="jsbn/jsbn.js"></script>
        <script type="text/javascript" src="jsbn/jsbn2.js"></script>
        <script type="text/javascript" src="UCrypt.js"></script>
        <script type="text/javascript" src="helpers.js"></script>
        <script type="text/javascript" src="pad.js"></script>
        <script type="text/javascript" src="cipher.js"></script>
        <script type="text/javascript" src="aes.js"></script>
        <script type="text/javascript" src="des.js"></script>
        <script type="text/javascript" src="signature.js"></script>
        <script type="text/javascript" src="ecfp.js"></script>
        <script type="text/javascript" src="keys.js"></script>
        <script type="text/javascript" src="ka.js"></script>
        <script type="text/javascript" src="ecdh.js"></script>
        <script type="text/javascript" src="ecdsa.js"></script>
        <script type="text/javascript" src="hash.js"></script>
        <script type="text/javascript" src="ripemd160.js"></script>
        <script type="text/javascript" src="rsa.js"></script>
        <script type="text/javascript" src="sha1.js"></script>
        <script type="text/javascript" src="sha256.js"></script>

