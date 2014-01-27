
JSUCrypt
========

## Introduction

A tiny, unified and simple Javascript Crypto Library.

The main goals of the library are:

     - provide an unified APIs for various cryptography operations
     - easy to extends
     - easy to reduce
     - easy to maintain
     - easy to use
    
This beta release of JSUCrypt does not feature performance at main goal, but it's not a naive implementation....

Current supported algorithms are:

     - hash: RIPMED160, SHA1, SHA224, SHA256, SHA384, SHA512
     - cipher: DES, AES, RSA
     - signature:  DES, AES, RSA, ECDSA, ECDSA with RFC6979
     - key agreement: ECDH/SVDP
     - padding: PKCS 1 (v1.5), PKCS 5, ISO9797M1, ISO9797M2

Comming algorithms are:

     - hash: MD5
     - signature: DSA
     - key agreement: DH


## Installation

### Get it 

  - Clone it :         git clone git@github.com:ubinity/JSUCrypt.git
  - Produce the dist : make dist

### Check it

In a console:

   - cd tests
   - ./test.sh

## Usage

Insert something like that in your html page:

        <script type="text/javascript" src="jsbn/jsbn.js"></script>
        <script type="text/javascript" src="jsbn/jsbn2.js"></script>
        <script type="text/javascript" src="JSUCrypt.js"></script>
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
        <script type="text/javascript" src="sha512.js"></script>

Read the documentation, staring with dist/doc/index.html.
