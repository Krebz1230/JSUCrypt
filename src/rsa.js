/*
************************************************************************
Copyright (c) 2013 UBINITY SAS,  Cédric Mesnil <cedric.mesnil@ubinity.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*************************************************************************
*/
/**
 * @project UCrypt
 * @author Cédric Mesnil <cedric.mesnil@ubinity.com>
 * @license Apache License, Version 2.0
 */



((UCrypt.signature && UCrypt.signature.RSA) && (UCrypt.cipher && UCrypt.cipher.RSA)) || (function (undefined) {

    // --------------------------------------------------------------------------
    //                                   Signature
    // --------------------------------------------------------------------------
    if (UCrypt.signature && !UCrypt.signature.RSA) {
        /** 
         * An RSA Signature
         * @lends  UCrypt.signature.RSA 
         * @class 
         * @parameter {UCrypt.hash}   hash       a hash
         * @parameter {UCrypt.padder} padder     a padder
         * @see UCrypt.signature
         * @see UCrypt.hash
         * @see UCrypt.padder
         */
        var sigrsa = function(hash, padder) {        
            if(!padder) {
                padder = UCrypt.padder.None;
            }
            this._padder = padder;
            this._hash = hash; 
            this.reset();
        };

        /**
         * @see UCrypt.signature#init
         */    
        sigrsa.prototype.init = function(key, mode) {
            if (mode == UCrypt.signature.MODE_SIGN) {
                if ( (! key instanceof UCrypt.key.RSAPrivateKey) && 
                     (! key instanceof UCrypt.key.CRTPrivateKey) ){
                    throw new UCrypt.UCryptException("Invalid 'key' parameter");
                }
            } else if (mode == UCrypt.signature.MODE_VERIFY) {
                if ( ! key instanceof UCrypt.key.RSAPublicKey) {
                    throw new UCrypt.UCryptException("Invalid 'key' parameter");
                }
            } else {
                throw new UCrypt.UCryptException("Invalid 'mode' parameter");
            }
            this._key = key;
            this._mode = mode;
        };
        /**
         * @see UCrypt.signature#reset
         * @function
         */
        sigrsa.prototype.reset     = UCrypt.signature._asymReset;
        /**
         * @see UCrypt.signature#update
         * @function
         */
        sigrsa.prototype.update    = UCrypt.signature._asymUpdate;
        /**
         * @see UCrypt.signature#sign
         * @function
         */
        sigrsa.prototype.sign      = UCrypt.signature._asymSign;
        /**
         * @see UCrypt.signature#verify
         * @function
         */
        sigrsa.prototype.verify    = UCrypt.signature._asymVerify;


        sigrsa.prototype._doSign = function (h) {            
            var klen = this._key.size/8;
            //padd
            var blk;
            blk = [].concat(this._hash.PKCS1_OID).concat(h);
            blk = this._padder.pad(blk, this._key.size/8, false);
            //sign
            blk = UCrypt.utils.anyToBigInteger(blk);
            blk = blk.modPow(this._key.d,this._key.n);
            return UCrypt.utils.normalizeByteArrayUL(blk.toByteArray(),klen);
        };

        sigrsa.prototype._doVerify = function (h, sig) {
            var klen = this._key.size/8;
            //decrypt
            var blk = UCrypt.utils.anyToBigInteger(sig);
            blk = blk.modPow(this._key.e,this._key.n);
            blk = UCrypt.utils.normalizeByteArrayUL(blk.toByteArray(),klen);
            //add missing zero
            
            blk = this._padder.unpad(blk, klen, false);
            var expected = [];
            var oidlen = 0;
            var oid = [];
            if (this._hash.PKCS1_OID) {                
                oid = this._hash.PKCS1_OID;
                expected.append(oid);
                oidlen = expected.length;
            }
            expected.append(h);
            //check length
            if (expected.length != oidlen + h.length) {
                return false;
            }
            //check OID
            for ( i = 0; i< oidlen; i++) {
                if (expected[i] != oid[i]) {
                    return false;
                }                
            }
            expected = expected.slice(oidlen);
            //check h
            for ( i = 0; i< h.length; i++) {
                if (expected[i] != h[i]) {
                    return false;
                }
            }
            return true;
        };

        UCrypt.signature.RSA  = sigrsa;
    }

    // --------------------------------------------------------------------------
    //                                   Cipher
    // --------------------------------------------------------------------------
    if (UCrypt.cipher && !UCrypt.cipher.RSA) {
        /** 
         * An RSA Cipher
         * @lends  UCrypt.cipher.RSA 
         * @class 
         * @parameter {UCrypt.padder} padder       a padder
         * @see UCrypt.cipher
         * @see UCrypt.padder
         */
        var ciphrsa = function(padder) {       
            if(!padder) {                
                padder = UCrypt.padder.None;
            }
            this._padder = padder;
            this.reset();
        };

        /**
         * @see UCrypt.cipher#init
         */
        ciphrsa.prototype.init = function(key, mode) {
            if (mode == UCrypt.cipher.MODE_DECRYPT) {
                if ( (! key instanceof UCrypt.key.RSAPrivateKey) && 
                     (! key instanceof UCrypt.key.CRTPrivateKey) ){
                    throw new UCrypt.UCryptException("Invalid 'key' parameter");
                }
            } else if (mode == UCrypt.cipher.MODE_ENCRYPT) {
                if ( ! key instanceof UCrypt.key.RSAPublicKey) {
                    throw new UCrypt.UCryptException("Invalid 'key' parameter");
                }
            } else {
                throw new UCrypt.UCryptException("Invalid 'mode' parameter");
            }
            this._key = key;
            this._enc_mode = mode;
        };
        
        /**
         * @see UCrypt.cipher#reset
         * @function
         */
        ciphrsa.prototype.reset     = UCrypt.cipher._asymReset;
        /**
         * @see UCrypt.cipher#update
         * @function
         */
        ciphrsa.prototype.update    = UCrypt.cipher._asymUpdate;
        /**
         * @see UCrypt.cipher#finalize
         * @function
         */
        ciphrsa.prototype.finalize  = UCrypt.cipher._asymFinalize;

        ciphrsa.prototype._doCrypt  = function(data) {
            var klen = this._key.size/8;
            //padd
            var blk;            
            blk = this._padder.pad(data, klen, true);
            blk = UCrypt.utils.anyToBigInteger(blk);
            //crypt
            blk = UCrypt.utils.anyToBigInteger(blk);
            blk = blk.modPow(this._key.e,this._key.n);
            blk = UCrypt.utils.normalizeByteArrayUL(blk.toByteArray(),klen);
            return blk;
        };

        ciphrsa.prototype._doDecrypt = function(data) {
            var klen = this._key.size/8;
            //decrypt
            var blk;
            blk = UCrypt.utils.anyToBigInteger(data);
            blk = blk.modPow(this._key.d,this._key.n);
            blk = UCrypt.utils.normalizeByteArrayUL(blk.toByteArray(),klen);
            //unpadd
            blk = this._padder.unpad(blk, klen, true);
            return blk;            
        };

        UCrypt.cipher.RSA     = ciphrsa; 

    }
    
 
    // --------------------------------------------------------------------------
    //                                   Keys
    // --------------------------------------------------------------------------

    /**
     * Public RSA key container.
     *
     * @param {number}      size     key size in bits 
     * @param {anyBN}       e        public exponent
     * @param {anyBN}       n        modulus
     * @class
     */
    UCrypt.key.RSAPublicKey = function (size, e, n) {       
        this.size     = size;
        this.e        = UCrypt.utils.anyToBigInteger(e);
        this.n        = UCrypt.utils.anyToBigInteger(n);
    };
    
    /**
     * Private RSA key container.
     *
     * @param {number}      size     key size in bits 
     * @param {anyBN}       d        private exponent
     * @param {anyBN}       n        modulus
     * @class     
     */
    UCrypt.key.RSAPrivateKey = function(size, d, n) {
        this.size     = size;
        this.d        = UCrypt.utils.anyToBigInteger(d);
        this.n        = UCrypt.utils.anyToBigInteger(n);
    };

    /**
     * Private RSA CRT key container.
     *
     * @param {number}      size     key size in bits 
     * @param {anyBN}       p        
     * @param {anyBN}       q        
     * @param {anyBN}       dp       
     * @param {anyBN}       dq       
     * @param {anyBN}       qinv     
     * @class
     */
    UCrypt.key.RSACRTPrivateKey = function(size, p, q, dp, dq, qinv) {
        this.size     = size;
        this.p        = UCrypt.utils.anyToBigInteger(p);
        this.q        = UCrypt.utils.anyToBigInteger(q);
        this.dp       = UCrypt.utils.anyToBigInteger(dp);
        this.dq       = UCrypt.utils.anyToBigInteger(dq);
        this.qinv     = UCrypt.utils.anyToBigInteger(qinv);
    };

}());