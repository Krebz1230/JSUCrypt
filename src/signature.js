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

/** 
 * 
 * ## Base definition for Signature.
 *  
 * All Signature support a unified API:
 * 
 *   - void reset()
 *   - void init(key, mode, [IV])
 *   - data sign(data) 
 *   - bool verify(data, sig) 
 * 
 * _key_ is byte array containing the key value.
 * 
 * _mode_ is one of :
 * 
 *  - UCrypt.cipher.MODE_SIGN
 *  - UCrypt.cipher.MODE_VERIFY
 * 
 * _sign_, return the signature.
 * 
 * _verify_ return true or false, depending on the provided signature has been verified or not.
 *
 * Signature are automatically re-initialized on power up and on final call 
 * with last used key and default empty parameters.
 *
 *
 *
 * ### Creating  signature
 * 
 * 
 * #### AES/DES
 * 
 * to create en DES/AES cipher:
 * 
 *  - new UCrypt.signature.[DES|AES](padder, chainMode)
 * 
 * _chainMode_ is one of :
 * 
 *    - UCrypt.cipher.MODE_CBC
 *    - UCrypt.cipher.MODE_CFB
 * 
 * _padder_ is the padder to use. See above.
 * 
 * #### ECDSA/RSA
 * 
 * to create en ECDSA/RSA signature:
 * 
 *    - new UCrypt.signature.XXX(hasher)
 * 
 * _hasher_ is a hasher object. 
 * 
 * 
 * #### Example
 *         
 *         //create SHA1 hasher
 *         var sha  = new  UCrypt.hash.SHA1();
 *         
 *         //create ECFp keys
 *         var pubkey,privkey,domain,ver;
 *         domain =  UCrypt.ECFp.getEcDomainByName("secp256k1");
 *         privkey = new UCrypt.key.EcFpPrivateKey(
 *             256, domain, 
 *             "f028458b39af92fea938486ecc49562d0e7731b53d9b25e2701183e4f2adc991");
 *         
 *         pubkey = new UCrypt.key.EcFpPublicKey(
 *             256, domain, 
 *             new UCrypt.ECFp.AffinePoint("81bc1f9486564d3d57a305e8f9067df2a7e1f007d4af4fed085aca139c6b9c7a",
 *                                         "8e3f35e4d7fb27a56a3f35d34c8c2b27cd1d266d5294df131bf3c1cbc39f5a91" ));
 *         
 *         //create signer
 *         var ecsig = new UCrypt.signature.ECDSA(sha);
 *         
 *         //sign abc string
 *         ecsig.init(privkey,  UCrypt.signature.MODE_SIGN);
 *         sig = ecsig.sign("616263");
 *         
 *         //verify
 *         ecsig.init(pubkey,  UCrypt.signature.MODE_VERIFY);
 *         ver = ecsig.verify("616263", sig);
 *         
 * 
 * ------------------------------------------------------------------------------------
 *
 * @namespace UCrypt.signature 
 **/
UCrypt.signature || (function (undefined) {
    /**
     * @lends  UCrypt.signature 
     */
    var sig = {
         /** @class UCrypt.signature.DES */
        DES: undefined,
        /** @class UCrypt.signature.AES */
        AES: undefined,
        /** @class UCrypt.signature.RSA */
        RSA: undefined,
        /** @class UCrypt.signature.ECDSA */
        ECDSA: undefined,
    };

    /** 
     * Sign mode 
     * @constant
     */
    sig.MODE_SIGN=1;
    /** 
     * Verify mode 
     * @constant
     */
    sig.MODE_VERIFY=2;

    /**  
     * CBC Mode  
     * @constant
     */
    sig.MODE_CBC = 1;
    /**  
     * CFB Mode  
     * @constant
     */
    sig.MODE_CFB = 2;


    /** 
     * Init the signature
     * @name UCrypt.signature#init
     * @function
     * @memberof  UCrypt.signature
     * @abstract
     * @param {key}    key          the key
     * @param {number} mode         MODE_SIGN or MODE_VERIFY 
     * @param {anyBA} [IV]   optional IV
     */       
    /** 
     * Reset the signature
     * @name UCrypt.signature#reset
     * @function
     * @memberof  UCrypt.signature
     * @abstract
     */
    /** 
     * Push more data into the signature
     * @name UCrypt.signature#update
     * @function
     * @memberof  UCrypt.signature
     * @abstract
     * @param {anyBA} data chunk to decrypt/encrypt
     */
    /** 
     * Finalize the signature process.
     *
     * After finialization the signature is automaticcaly reset and ready to sign/verify.
     *
     * @name UCrypt.signature#sign
     * @function
     * @memberof  UCrypt.signature
     * @abstract
     * @param  {anyBA}  data  chunk to encrypt before finalization
     * @return {byte[]}       the signature
     */
    /** 
     * Finalize the signature process and check it
     *
     * After finialization the signature is automaticcaly reset and ready to encrypt/decrypt.
     *
     * @name UCrypt.signature#verify
     * @function
     * @memberof  UCrypt.signature
     * @abstract
     * @param  {anyBA} data   chunk to encrypt before finalization
     * @param  {anyBA} sig    signature to check
     * @return {boolean}      true or false
     */
    
    

    /* ------- Asymetric helper ------ */
    sig._asymReset = function() {
        this._hash.reset();
    };

    sig._asymUpdate = function(data) {
        try {
            data = UCrypt.utils.anyToByteArray(data);
            this._hash.update(data);        
        } catch(e) {
            this.reset();
            throw e;
        }
    };

    sig._asymSign = function(data) {
        try {
            data = UCrypt.utils.anyToByteArray(data);
            var h = this._hash.finalize(data);
            var s = this._doSign(h);
            this.reset();
            return s;
        } catch(e) {
            this.reset();
            throw e;
        }
    };

    sig._asymVerify = function(data, sig) {
       try {
           data = UCrypt.utils.anyToByteArray(data);
           var h = this._hash.finalize(data);
           var v = this._doVerify(h,sig);
           this.reset();
           return v;
       } catch(e) {
           this.reset();
           throw e;
       }
    };

    /* ------- Symetric helper ------ */
    sig._symReset  = function() {
        if (this._IV) {
            this._block     = [].concat(this._IV);
        } else {
            this._block     = [0,0,0,0,0,0,0,0];
        }
        this._remaining = [];
    };
    
    sig._symUpdate = function(data) {
        try {
            var i;
            data = UCrypt.utils.anyToByteArray(data);
            data = this._remaining.concat(data);
            this._remaining = [];
            switch(this._chain_mode) {
                //CBC
            case  UCrypt.signature.MODE_CBC:
                while (data.length >= this._blockSize) {
                    //xor
                    for (i = 0; i<8; i++) {
                        this._block[i] ^=  data[i];
                    }
                    data = data.slice(8);
                    //crypt
                    this._block = this._doEncryptBlock(this._block);
                }
                break;
                
                //CFB
            case UCrypt.signature.MODE_CFB:
                while (data.length >= this._blockSize) {
                    //crypt
                    this._block = this._doEncryptBlock(this._block);
                    //xor
                    for (i = 0; i<8; i++) {
                        this._block[i] ^=  data[i];
                    }
                    data = data.slice(8);
                }
                break;
                
                //WAT
            default:
                throw new UCrypt.UCryptException("Invalid 'chain mode' parameter");
            }
            this._remaining = data;
        } catch(e) {
            this.reset();
            throw e;
        }        
    };
    
    sig._symSign = function(data) {
        try {
            data = UCrypt.utils.anyToByteArray(data);
            data = this._remaining.concat(data);
            this._remaining = [];
            data = this._padder.pad(data, this._blockSize);
            this.update(data);
            var sig = [].concat(this._block);
            this.reset();
            return sig;
        } catch(e) {
            this.reset();
            throw e;
        }
    };

    sig._symVerify = function(data, sigToCheck) {
        try {
            sigToCheck = UCrypt.utils.anyToByteArray(sigToCheck);
            data = UCrypt.utils.anyToByteArray(data);
            data = this._remaining.concat(data);
            this._remaining = [];
            this._padder.pad(data, this._blockSize);
            this.update(data);
            var sig = [].concat(this._block);
            this.reset();
            
            if (sigToCheck.length != sig.length) {
                return false;
            }
            for (var i = 0; i<this._block.length; i++) {
                if (sig[i] != sigToCheck[i]) {
                    return false;
                }
        }
            return true;
        } catch(e) {
            this.reset();
            throw e;
        }
    };

    // --- set it ---
    UCrypt.signature = sig;
}());



