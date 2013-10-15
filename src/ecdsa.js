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
 * @project JSUCrypt
 * @author Cédric Mesnil <cedric.mesnil@ubinity.com>
 * @license Apache License, Version 2.0
 */



// --------------------------------------------------------------------------
//                                   ECDSA
// --------------------------------------------------------------------------

JSUCrypt.signature.ECDSA  ||  (function (undefined) {
    /** 
     * An ECDSA Signature
     * @class  JSUCrypt.signature.ECDSA
     * @param {JSUCrypt.hash} hasher an hasher
     * @see JSUCrypt.cipher
     * @see JSUCrypt.hash
     */
    JSUCrypt.signature.ECDSA = function(hash) {        
        this._hash = hash; 
        this.reset();
    };

    /**
     * @see JSUCrypt.signature#init
     */    
    JSUCrypt.signature.ECDSA.prototype.init = function(key, mode) {
        if (mode == JSUCrypt.signature.MODE_SIGN) {
            if ( ! key instanceof JSUCrypt.key.EcFpPrivateKey) {
                throw new JSUCrypt.JSUCryptException("Invalid 'key' parameter");
            }
        } else if (mode == JSUCrypt.signature.MODE_VERIFY) {
            if ( ! key instanceof JSUCrypt.key.EcFpPublicKey) {
                throw new JSUCrypt.JSUCryptException("Invalid 'key' parameter");
            }
        } else {
            throw new JSUCrypt.JSUCryptException("Invalid 'mode' parameter");
        }
        this._key = key;
        this._mode = mode;
        this.reset();
    };
    /**
     * @param {X} X X   
     * @see JSUCrypt.signature#reset
     * @function
     */
    JSUCrypt.signature.ECDSA.prototype.reset     = JSUCrypt.signature._asymReset;
    /**
     * @param {X} X X   
     * @see JSUCrypt.signature#update
     * @function
     */
    JSUCrypt.signature.ECDSA.prototype.update    = JSUCrypt.signature._asymUpdate;
    /**
     * @param {X} X X   
     * @see JSUCrypt.signature#sign
     * @function
     */
    JSUCrypt.signature.ECDSA.prototype.sign      = JSUCrypt.signature._asymSign;
    /**
     * @param {X} X X   
     * @see JSUCrypt.signature#version
     * @function
     */
    JSUCrypt.signature.ECDSA.prototype.verify    = JSUCrypt.signature._asymVerify;

    JSUCrypt.signature.ECDSA.prototype._doSign = function (h) {  
        var order = this._key.domain.order;        

        h = new BigInteger(JSUCrypt.utils.byteArrayToHexStr(h),16);

        for(;;) {
            //peek random
            var k = [];
            var i = this._key.size>>>3;
            while (i--) {
                //k.push(Math.floor(Math.random()*255));
                k.push(42);
            }
            k = JSUCrypt.utils.byteArrayToHexStr(k);
            k = new BigInteger(k,16);
            k = k.mod(order);
            
            //compute kG
            var  kG   = this._key.domain.G.multiply(k);
            
            //extract sig r,s
            var  x     = kG.x.mod(order);
            if (k.equals(BigInteger.ZERO)) {
                continue;   
            }
            var  kinv  = k.modInverse(order);
            var  dx    = this._key.d.multiply(x).mod(order);
            var  h_dx  = h.add(dx).mod(order);
            var  y     = (kinv.multiply(h_dx)).mod(order); 
            if (y.equals(BigInteger.ZERO)) {
                continue;   
            }
            break;
        } 
        var r = x.toByteArray();
        var s = y.toByteArray();
        
        r = [0x02, r.length].concat(r);
        s = [0x02, s.length].concat(s);
        
        return [0x30, r.length+s.length].concat(r).concat(s);        
    };

    JSUCrypt.signature.ECDSA.prototype._doVerify = function(h, sig) {
        sig = JSUCrypt.utils.anyToByteArray(sig);
        var order = this._key.domain.order;

        //finalize hash        
        h = new BigInteger(JSUCrypt.utils.byteArrayToHexStr(h),16);

        //extract r/s
        var r = sig.slice(4,4+sig[3]);
        var s = sig.slice(4+sig[3]+2);

        s = new BigInteger(JSUCrypt.utils.byteArrayToHexStr(s),16);
        r = new BigInteger(JSUCrypt.utils.byteArrayToHexStr(r),16);

        //check format
        var offset =  4+ (sig[3]&0xFF);
        if ((sig[0] != 0x30)                         ||
            (sig[1] != (4+sig[3]+sig[offset+1]))     ||
            (sig[2] != 0x02)                         ||
            (sig[offset] != 0x02)) {
            return false;
        }
        //precheck r/s
        var order_1 = order.subtract(BigInteger.ONE);

        if ((r.compareTo(order_1)>=0) ||
            (r.compareTo(order_1)>=0)){
            return false;
        }
        
        var w   = s.modInverse(order); 
        var u1  = (h.multiply(w)).mod(order);
        var u2  = (r.multiply(w)).mod(order);
        var u1G = this._key.domain.G.toProjective().multiply(u1);
        var u2Q = this._key.W.toProjective().multiply(u2);

        var xy  = u2Q.add(u1G).toAffine();
        var verified =  xy.x.mod(order).equals(r);
        return verified;
    };

}());
