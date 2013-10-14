var test_hash         = true;

var test_ecfp         = true;
var test_sign_ecdsa   = true;
var test_sign_rsa     = true;
var test_sign_des     = true;

var test_ciph_des     = true;
//var test_ciph_aes     = true;
var test_ciph_rsa     = true;

var test_ka_ecdh      = true;

var  hasFailure = false;
var  globalReport = {};


var cipher;
var signature;

function report(name, status) {
    globalReport[name] = status;
}

function printReport()  {
    print();
    print("=====================================================================");
    for (var k in globalReport) {
        print(pad20(k) + ": " +  (globalReport[k]?"FAIL":"SUCCESS"));
    }

    function pad20(str) {
        while(str.length <20) {
            str = str+" ";
        }
        return str;
    }
}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
//                                    DES
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
function des_ciph_test(cipher, key, vec, m1hax) {
    var i, ct,pt0,pt,blk;
    
    //test encrypt
    print("    encrypt/finalize");
    for (i = 0; i<vec.length; i++) {
        cipher.init(key, JSUCrypt.cipher.MODE_ENCRYPT, vec[i][2]);
        ct = cipher.finalize(vec[i][0]);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;            
        }
    }
    print("    encrypt/update");
    for (i = 0; i<vec.length; i++) {
        cipher.init(key, JSUCrypt.cipher.MODE_ENCRYPT, vec[i][2]);
        ct = [];
        pt = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = pt.slice(0,5);
            pt = pt.slice(5);
            ct = ct.concat(cipher.update(blk));
        }
        ct = ct.concat(cipher.finalize(pt));
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }


    //test decrypt
    print("    decrypt/finalize");
    for (i = 0; i<vec.length; i++) {
        cipher.init(key, JSUCrypt.cipher.MODE_DECRYPT, vec[i][2]);
        pt = cipher.finalize(vec[i][1]);
        pt = JSUCrypt.utils.byteArrayToHexStr(pt);
        pt0 = vec[i][0];
        if (m1hax) {
            pt0 = JSUCrypt.utils.anyToByteArray(pt0);
            while ((pt0.length % 8)!=0) {
                pt0.push(0);
            }
            pt0 = JSUCrypt.utils.byteArrayToHexStr(pt0);
        } 
        if (pt0.equals(pt)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }    
    print("    decrypt/update");
    for (i = 0; i<vec.length; i++) {
        cipher.init(key, JSUCrypt.cipher.MODE_DECRYPT, vec[i][2]);
        pt = [];
        ct = JSUCrypt.utils.anyToByteArray(vec[i][1]);
        while (pt.length>5) {
            blk = ct.slice(0,5);
            ct = ct.slice(5);
            pt = pt.concat(cipher.update(blk));
        }
        pt = pt.concat(cipher.finalize(ct));
        pt = JSUCrypt.utils.byteArrayToHexStr(pt);
        pt0 = vec[i][0];
        if (m1hax) {
            pt0 = JSUCrypt.utils.anyToByteArray(pt0);
            while ((pt0.length % 8)!=0) {
                pt0.push(0);
            }
            pt0 = JSUCrypt.utils.byteArrayToHexStr(pt0);
        } 
        if (pt0.equals(pt)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }

    print("");
}


if (test_ciph_des)  {
    print("====================================================================");
    print("                        DES CIPHER TESTING                          ");
    print("====================================================================");

    // ------------------------------------------------------------------
    print("---                      DES/ECB/NOPAD                 ---*/");
    hasFailure = false;
    var key_simple_ecb_nopad = new JSUCrypt.key.DESKey("466431296486ed9c");
    var vector_simple_ecb_nopad = [
        ["d71fc207254820a2","5110b62204e0e8af"],
        ["506b4e5b8c8fa4db1b95d3e8c5c5fb5a","77147871593f5657df031a8df2b184e0"],
    ];

    var key_triple2_ecb_nopad = new JSUCrypt.key.DESKey("46911e963f3af1b59d58e36af67fc7b7");
    var vector_triple2_ecb_nopad = [
        ["3e83be859e0058b5","865166a54b3e61a7"],
        ["02513c3f5764c1eeabdac42ce54f4a47","df275f5c4ac4f85e423d580392e9b37e"],
    ];

    var key_triple3_ecb_nopad = new JSUCrypt.key.DESKey("d044c68cc84e5c60063c8934d06e2158ff87b44e688063aa");
    var vector_triple3_ecb_nopad = [
        ["befabbd8bcc0458d","7fcb4d10025de43b"],
        ["f5319b4ea6c8ad587d41d9a1f6b3c432","81229e8fec7ad07428b768dbae2d3268"],
    ];

    cipher = new JSUCrypt.cipher.DES(JSUCrypt.padder.None, JSUCrypt.cipher.MODE_ECB);

    print("  64b its key");
    des_ciph_test(cipher, key_simple_ecb_nopad,  vector_simple_ecb_nopad);
    print("  128 bits key");
    des_ciph_test(cipher, key_triple2_ecb_nopad,  vector_triple2_ecb_nopad);
    print("  192 bits key");
    des_ciph_test(cipher, key_triple3_ecb_nopad,  vector_triple3_ecb_nopad);

    report("Cipher DES/ECB/NOPAD", hasFailure);


    // ------------------------------------------------------------------
    print("---                    DES/ECB/ISO9797M1               ---*/");
    hasFailure = false;
    var key_simple_ecb_9797m1 = new JSUCrypt.key.DESKey("466431296486ed9c");
    var vector_simple_ecb_9797m1 = [
        ["d71fc207254820a2","5110b62204e0e8af"],
        ["c4a85aeb0b2041","b6ad24875b0edf65"],
        ["494f8bf1f8cd30f1","a488e1afbebe075b"],
        ["1394223cf8a8299580","637b7dccd44b4f898988804b5e754b1e"],
        ["4957876e9fa71163506b4e5b8c8fa4","2f8bd3138ff8e403968bf09e255f9d9a"],
        ["db1b95d3e8c5c5fb5ae737529060e710","f7bf0a0a37a26fdf6084d762eb14e13b"],
    ];

    var key_triple2_ecb_9797m1 = new JSUCrypt.key.DESKey("227ad947c4cf8d00f4bbb8b811b03a2f");
    var vector_triple2_ecb_9797m1 = [
        ["36aa5c33176cdc1a","e3815ced0a630da8"],
        ["1c562367189c05","68f5488f49a7e8ac"],
        ["3a16df82dbae0fdb","c6e5a01cb4f9cb64"],
        ["a2cb935adc44940b7a","a562d87308137f8492fea0e08c4739a3"],
        ["3f67ad56d38970efdf9356f72f5b32","42cabe4c0fb01524a3b8047c6bd720f0"],
        ["463ab421e8c3fc8a8e8fe46ad379754d","a1f13bcbf2e3d6d12b5b3bc96567b2bf"],
    ];

    var key_triple3_ecb_9797m1 = new JSUCrypt.key.DESKey("3874b13c8ce7ecc1cb40ac99e3fc8e4a4da6fa4816c118e6");
    var vector_triple3_ecb_9797m1 = [
        ["b572c2a54b1a7483","ac90b04dc4e1a920"],
        ["8f26c01b0dacdc","fec0cd5cf4e1b34e"],
        ["d8ec8871cf850019","4b561d213763543b"],
        ["d2a6131bbcd433a389","7f73af6fc8f3b35a180bcdadd35f50c3"],
        ["a5652ef180a3740fc9342ad6e006af","a6cdfc5d9e8617c1ddc2493d9bef2a8b"],
        ["cc8f209b1420b4e6c6c701839b352624","9796aee5604230bc6ea9bb575377a073"],
    ];

    cipher = new JSUCrypt.cipher.DES(JSUCrypt.padder.ISO9797M1, JSUCrypt.cipher.MODE_ECB);

    print("  64b its key");
    des_ciph_test(cipher, key_simple_ecb_9797m1,   vector_simple_ecb_9797m1, true);
    print("  128 bits key");
    des_ciph_test(cipher, key_triple2_ecb_9797m1,  vector_triple2_ecb_9797m1,true);
    print("  192 bits key");
    des_ciph_test(cipher, key_triple3_ecb_9797m1,  vector_triple3_ecb_9797m1,true);
    report("Cipher DES/ECB/ISO9797M1", hasFailure);



    // ------------------------------------------------------------------
    print("---                    DES/ECB/ISO9797M2               ---*/");
    hasFailure = false;
    var key_simple_ecb_9797m2 = new JSUCrypt.key.DESKey("466431296486ed9c");
    var vector_simple_ecb_9797m2 = [
        ["","8988804b5e754b1e"],
        ["d71fc207254820","59c272b5ea15fafd"],
        ["a2c4a85aeb0b2041","bdb680d4cba1420e8988804b5e754b1e"],
        ["494f8bf1f8cd30f113","a488e1afbebe075bcd00b2e17f7fc697"],
        ["94223cf8a82995804957876e9fa711","9d6dd8aba905aa0bca3d890143edb0de"],
        ["63506b4e5b8c8fa4db1b95d3e8c5c5fb","51257f8da7187f6af7bf0a0a37a26fdf8988804b5e754b1e"],
    ];

    var key_triple2_ecb_9797m2 = new JSUCrypt.key.DESKey("7876e970a2e834193e9b9c858f067ad6");
    var vector_triple2_ecb_9797m2 = [
        ["","cea63727cd07efda"],
        ["07c333fba58c16","1f6c87fe8965d084"],
        ["d268d51bd36f84c8","f77496fcd3a517dfcea63727cd07efda"],
        ["e8fab1589c998cb5d7","babe690a88fb8cb510261dabef4c0ebc"],
        ["28515cb757d68d5e99c0593e4c6f10","5ce8490ef173a68e11ac4331ec505467"],
        ["b4452c87b4b0509caa01f4469b81fb72","bc6b1c101592e0722239c17a97c0cb98cea63727cd07efda"],
    ];

    var key_triple3_ecb_9797m2 = new JSUCrypt.key.DESKey("cba05370f80e17bb8d5c57de3bef602546779e01ea18ef5a");
    var vector_triple3_ecb_9797m2 = [
        ["","f884c7e2f0313355"],
        ["7c16e52d2213e7","18438b24e75b2c41"],
        ["edb43a5eac487567","d47889554dfb533af884c7e2f0313355"],
        ["d5d1bfb30dae1332f4","1796c0bf5e40e97e56bb816348321e44"],
        ["8ad1f575e9e4cf66fab4931dc87a0a","b55663622913719a06e445066df44e6d"],
        ["7cb46828fcdd8fd1af4e84bcfc98eef1","59787b3cd747e60074aaf91e5ccf0d49f884c7e2f0313355"],
    ];

    cipher = new JSUCrypt.cipher.DES(JSUCrypt.padder.ISO9797M2, JSUCrypt.cipher.MODE_ECB);

    print("  64b its key");
    des_ciph_test(cipher, key_simple_ecb_9797m2,   vector_simple_ecb_9797m2);
    print("  128 bits key");
    des_ciph_test(cipher, key_triple2_ecb_9797m2,  vector_triple2_ecb_9797m2);
    print("  192 bits key");
    des_ciph_test(cipher, key_triple3_ecb_9797m2,  vector_triple3_ecb_9797m2);

    report("Cipher DES/ECB/ISO9797M2", hasFailure);
    

    // ------------------------------------------------------------------
    print("---                      DES/CBC/NOPAD                 ---*/");
    hasFailure = false;
    var key_simple_cbc_nopad = new JSUCrypt.key.DESKey("466431296486ed9c");
    var vector_simple_cbc_nopad = [
        ["d71fc207254820a2","5110b62204e0e8af"],
        ["506b4e5b8c8fa4db1b95d3e8c5c5fb5a","77147871593f5657abcccf39003330be"],
        ["63c1f186eb440050ce45bd76bded8d0c", "6b9d512180d0980103c397247e4406aa", "7c721d175a83b034"],
    ];

    var key_triple2_cbc_nopad = new JSUCrypt.key.DESKey("e634b2877cd10a3702fd03ee68191e0b");
    var vector_triple2_cbc_nopad = [
        ["cd4b57a20cf18ce7","42ba35433f1007f8"],
        ["4701495df4e2591b2ddcbf496a9a68f5","74b41740ecfe7996da21a095683f54fe"],    
        ["03cc2638a77afb0dd9a2f2da529a531b4ee19df8851b90e5abf8abf470beda738a00ab317aa63f5348312e9acb81b519625311e86ea1cd199a780d0a37e87dc1e828f363ce32b61663e4b12e656647c8b958b027f97d4093f54e9d2c361aee1e42e18110133827761cd8a4823eeb4af843fa1f3c7760d06cae6d99e4888702ca6884db7bbc02f1d8da955a1880a410c39e30ff1590cf823e3d1b22c5a2248f0aa86a85646c763d46", "144c81bfe1e3e6f01caeefd4590f192b5f74123e95b601b144c6c316b4f6a1906ce53e1d65a2dba75821decb2239aefc3aa56a2cc0dab998fdf22071eb4287c4fa40c214696ac30cad17bc0464f6d9812580422c19df09a33f2dc86bf560a5814eb93ed26d6941c768c00c0ef6843d5dd057ffd5b553487e9265a18e9d22e2a269cf34d0aa1a8d94573004e7f211cda843b9d7ccf58f6e845eca8ca8ff9f32db1e71fecbe7536803", "5f9068c6497713e6"],
    ];

    var key_triple3_cbc_nopad = new JSUCrypt.key.DESKey("a5be277f300a0e3891669a9b3472c9e934588dd4d4e63c44");
    var vector_triple3_cbc_nopad = [
        ["851e35e84b4d0af0","a2a2568674a41586"],
        ["1d8d6a580add25edea8d046abe041e48","da115dd8aadd3f764e878bbbee4bf4c0"],
        ["f2209d8f6f7a05f9e4986147110f42a3fbc70a993fcb8ed300afbaff9136228357bf12c63917c01daf2164c131a7642c6e6ec5ad3953803a023a3994715b17c81a2a8e54414e71f170d6b2a17d16cdeb859298bee518f8e853317cc48c938ca7bd1afbff696cf0d942a27abfb847aa3dd942fcbe5bf4a6ae262272b2b6fe597318547281c1625a0304d4c3bd1b6dfaf4b0f6b30beb59b911", "c5093704ca7ff02f11902e1baa78c3e23e7f3e1876d4b14dee05824d2b82fe722ceb2bba72ad540f5a0f867f1894238d6a2414b05cffd7a3adf4ed091535cbeb9cc4604fad5de744b87baafd6e1b86c7af8eafa4776aa9481d2c63e7096e9dabf1a004f444ede03125626e52430b8b2bad147c212aea520f8123bf335b52ed03babaf7059d3490cff9c01d3f146870b3e718566f5019a3f6", "943520e6fee27c23"],
    ];

    cipher = new JSUCrypt.cipher.DES(JSUCrypt.padder.None, JSUCrypt.cipher.MODE_CBC);

    print("  64b its key");
    des_ciph_test(cipher, key_simple_cbc_nopad,   vector_simple_cbc_nopad);
    print("  128 bits key");
    des_ciph_test(cipher, key_triple2_cbc_nopad,  vector_triple2_cbc_nopad);
    print("  192 bits key");
    des_ciph_test(cipher, key_triple3_cbc_nopad,  vector_triple3_cbc_nopad);

    report("Cipher DES/CBC/NOPAD", hasFailure);
    hasFailure = false;
    
}

function des_sign_test(signature, key, vec) {
    var i, ct,pt,blk;
    
    //test sign
    print("    sign/finalize");
    for (i = 0; i<vec.length; i++) {
        signature.init(key, JSUCrypt.signature.MODE_SIGN, vec[i][2]);
        ct = signature.sign(vec[i][0]);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;            
        }
    }
    print("    sign/update");
    for (i = 0; i<vec.length; i++) {
        signature.init(key, JSUCrypt.signature.MODE_SIGN, vec[i][2]);
        ct = [];
        pt = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = pt.slice(0,5);
            pt = pt.slice(5);
            signature.update(blk);
        }
        ct = signature.sign(pt);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }

    //test verify
    print("    verify/finalize");
    for (i = 0; i<vec.length; i++) {
        signature.init(key, JSUCrypt.signature.MODE_VERIFY, vec[i][2]);
        pt = signature.verify(vec[i][0], vec[i][1]);
        if (pt) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }    
    print("    verify/update");
    for (i = 0; i<vec.length; i++) {
        signature.init(key, JSUCrypt.signature.MODE_VERIFY, vec[i][2]);
        pt = [];
        ct = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = ct.slice(0,5);
            ct = ct.slice(5);
            pt = pt.concat(signature.update(blk));
        }
        pt = pt.concat(signature.verify(ct, vec[i][1]));
       
        if (pt) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }

    print("");
}


if (test_sign_des)  {
    print("====================================================================");
    print("                      DES SIGNATURE TESTING                         ");
    print("====================================================================");

    print("---                      DES/CBC/NOPAD                 ---*/");
    hasFailure = false;
    var key_sign_simple_cbc_nopad = new JSUCrypt.key.DESKey("9d58e36af67fc7b7");
    var vector_sign_simple_cbc_nopad = [
        ["3e83be859e0058b5","29bf8382c4eb1188"],
        ["02513c3f5764c1eeabdac42ce54f4a47","1eb2200a8ad996e7"],
        ["4aba21f12fe87d9f273fbec88ded0f78fce3ab96a0d1069b48705360003b254af5463b252eb8c455f8821e85702dfd6c10a803b07a094bc2799e227ad947c4cf8d00f4bbb8b811b03a2f36aa5c33176cdc1a1c562367189c053a16df82dbae0fdba2cb935adc44940b7a3f67ad56d38970efdf9356f72f5b32463ab421e8c3fc8a8e8fe46ad379754db8dcfb0eaf847e9e6411f45b40508d868a41a77305a3fd9333e2fe065b735413504f21ffd39f9e37b09293f0e220776d621ee067c2ddfaf5bff8fb1a6c4f2dbc9e4ebb72ed59a99dec3c8ece5d053bbf231b26e5f920dab819d6d385250041c44ffc363c56dfda421c6810796d4c3890675e76607e50199726ec1c4cec5d103b5a4678b02552f241ba02ba274ef2b7b6502d16cf7e2f66a41b83f008e000433a46bbea6c0ddcadc7df68ee2d5aa6e3abd3fa7a5129e0f64563e64d44e7907e2d4c69995945472124af0f5209b535b4892f2eda590fd09e72b7ebb69e7b35cbc79e6521e3ac42085b515a64078f1990bf476a18563bb6c9f2a17f901cb45be452c005366c473ec798982c9f27452fe68c9afee3d5b4acc7552b5772e0b25632735b68dfa2a6a73a3ed3da6618094ca4a34b8778ff333f555f96c73f491d71bc78da9b1a804254bf152e252d3871d2dbbc5954bc8d9311ec2ad82b73f59c2f6d", "faacfa0ffa8b9c22", "fb766ab81890e7c4"],
    ];

    var key_sign_triple2_cbc_nopad = new JSUCrypt.key.DESKey("24e7e961efdeecb4c8f3467a82c34a26");
    var vector_sign_triple2_cbc_nopad = [
        ["bf78a605da72e28f","894fa0a66d7b65ec"],
        ["91669a9b3472c9e934588dd4d4e63c44","0b38534e0e99ca77"],    
        ["d912f7ed85f3f99f9ce27ddf06ef10edc564ae9dbbae9bb5", "9c1fa4986dc41e8a", "f9a2e12896a2a2c4"],
    ];

    var key_sign_triple3_cbc_nopad = new JSUCrypt.key.DESKey("a048028e1eb63357714ea916e81579ddab64d532490a90b7");
    var vector_sign_triple3_cbc_nopad = [
        ["1169e8ac4e842cee","4c06c5770f4774cb"],
        ["bc916ea142b0f7419b64289c49ec4793","21b2cfd83e3bf429"],
        ["83e132cdcd7960529e857a31f5579c96942cee5fd1cae608140e800e2e3aa4b11bd67ee950de3bee64b620590dbcefa1e8de01baa8e7c2bcf642ca247c6fd5984554819532bc849672a4ef7f60df2148bd22026509c421ff07eb23835af91ba04d9c357f59b916cb5d054bbde46c06a18e080697cd2797d413ba576db3730d000f438068fc96345a9b7f1780eb1d2179262810f34fa7c762621ed01591dd16a12096091d2c3d77c7bc8e47a7ac6920d29131c5e0d88c433aaa13503cf066dd11fce62e2824a5efe0333788dfa0a8b131d97611b20254ecad673ce958a2c6699eac97c6d03cb6b16fed394f8de100bebb77cf6d792459268b960fe338d54cd782e39d521f53038f403cdecd1ede8bd9555b46cf7f9ff50a3505ee6eda3a455c1ee2af3d36b2cc76efaa440d89cfe6de2a2cada9cba3b401a8a26f82dcb4dffa968e38cc4004432faf873c38562216814ec42a1a67de1b0f808a915d3e7057d4fe8fa13f94e46e436bab7bc1cd91421c556d36bc4b51cbccdb5d2919cd80edcc108e0ba47279e7dd24629ff2f3e10e494e44059a95d166702e8f89fb0f76c71f05d2c3774caa55700cf46200d5704924b44ebe491f24b94db34249c2b910e2bee3", "9f3b5f4ccb6f8320", "364a2878fa1fb996"],
    ];

    signature = new JSUCrypt.signature.DES(JSUCrypt.padder.None, JSUCrypt.signature.MODE_CBC);

    print("  64b its key");
    des_sign_test(signature, key_sign_simple_cbc_nopad,   vector_sign_simple_cbc_nopad);
    print("  128 bits key");
    des_sign_test(signature, key_sign_triple2_cbc_nopad,  vector_sign_triple2_cbc_nopad);
    print("  192 bits key");
    des_sign_test(signature, key_sign_triple3_cbc_nopad,  vector_sign_triple3_cbc_nopad);

    report("Signature DES/CBC/NOPAD", hasFailure);
    hasFailure = false;

}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
//                                    RSA
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------


function rsa_cipher_test(cipher, pubkey, privkey, vec, nopad) {
    var i, ct,pt,blk,pt0;

   //test decrypt
    print("    decrypt/finalize");
    for (i = 0; i<vec.length; i++) {
        cipher.init(privkey, JSUCrypt.cipher.MODE_DECRYPT);
        pt = cipher.finalize(vec[i][1]);
        pt = JSUCrypt.utils.byteArrayToHexStr(pt);
        pt0 = vec[i][0];        
        if (pt0.equals(pt)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            print("        "+vec[i][1]);
            print("        "+pt);
            hasFailure = true;
        }
    }    
    print("    decrypt/update");
    for (i = 0; i<vec.length; i++) {
        cipher.init(privkey, JSUCrypt.cipher.MODE_DECRYPT);
        pt = [];
        ct = JSUCrypt.utils.anyToByteArray(vec[i][1]);
        while (pt.length>5) {
            blk = ct.slice(0,5);
            ct = ct.slice(5);
            pt = pt.concat(cipher.update(blk));
        }
        pt = pt.concat(cipher.finalize(ct));
        pt = JSUCrypt.utils.byteArrayToHexStr(pt);
        pt0 = vec[i][0];       
        if (pt0.equals(pt)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            print("        "+vec[i][1]);
            print("        "+pt);
            hasFailure = true;
        }
    }

    //test encrypt
    print("    encrypt/finalize");
    for (i = 0; i<vec.length; i++) {
        cipher.init(pubkey, JSUCrypt.cipher.MODE_ENCRYPT);
        ct = cipher.finalize(vec[i][0]);
        cipher.init(privkey, JSUCrypt.cipher.MODE_DECRYPT);
        ct = cipher.finalize(ct);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][0].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;            
        }
    }

    print("    encrypt/update");
    for (i = 0; i<vec.length; i++) {
        cipher.init(pubkey, JSUCrypt.cipher.MODE_ENCRYPT);
        ct = [];
        pt = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = pt.slice(0,5);
            pt = pt.slice(5);
            ct = ct.concat(cipher.update(blk));
        }
        ct = ct.concat(cipher.finalize(pt));
        if (nopad) {
            ct = JSUCrypt.utils.byteArrayToHexStr(ct);
            if (vec[i][1].equals(ct)) {
                print("      "+i+" : OK");
            } else {
                print("      "+i+" : NOK");
                print("        "+vec[i][1]);
                print("        "+ct);
                hasFailure = true;
            }
        } else {
            cipher.init(privkey, JSUCrypt.cipher.MODE_DECRYPT);
            ct = cipher.finalize(ct);
            ct = JSUCrypt.utils.byteArrayToHexStr(ct);
            if (vec[i][0].equals(ct)) {
                print("      "+i+" : OK");
            } else {
                print("      "+i+" : NOK");
                hasFailure = true;
            }
        }
    }
}

if (test_ciph_rsa) {
    var rsaciph;  
    var rsaciphpubkey, rsaciphprivkey, rsaciphcrtkey;
    var rsaciphvector;

    print("====================================================================");
    print("                           RSA CIPHER TESTING                       ");
    print("====================================================================");
    // --- 1024/nopad ---
    rsaciph = new JSUCrypt.cipher.RSA(JSUCrypt.padder.None);
    rsaciphpubkey = new JSUCrypt.key.RSAPublicKey(1024, 
                                         "00010001",
                                         "AAF9865E2AC9F4D2BF31A9F22B76DB32FCD19E8748EA687D2401F7DB1DA8D514633FF5F7C164BE8E4E63DEFCA09FD82816E5BBB171E40C99B60C8EA0E78EBB9DA9C3D16D8BA736E700153BA241B2BC7AEB8CEFF133BEA2640A759F0671A6910E1B04F7244C0F78296080C0E4EE8118D36A21572B8F1D3BD8EDAA13FB4BE19827");
    rsaciphprivkey = new JSUCrypt.key.RSAPrivateKey(1024,
                                           "106981777A9E064D50A320D02951F07AB5801DBA98CA3F9B7BA060BD7CDC5F0FE4F317D65F8F1F27A3E8BC57FDC73A45A6E5089E60F3662E3F26776E84ABD3E0876537E6EBCCAE0C415606DBEFF706D529F3BE735959AC21D86B4C087D4084AA0BD9BBDB685B215E8547FCBAE0148BB3CE82836A6E0B2B274F5117B5722BE961",
                                           "AAF9865E2AC9F4D2BF31A9F22B76DB32FCD19E8748EA687D2401F7DB1DA8D514633FF5F7C164BE8E4E63DEFCA09FD82816E5BBB171E40C99B60C8EA0E78EBB9DA9C3D16D8BA736E700153BA241B2BC7AEB8CEFF133BEA2640A759F0671A6910E1B04F7244C0F78296080C0E4EE8118D36A21572B8F1D3BD8EDAA13FB4BE19827");

    rsaciphvector = [
        ["006431296486ed9cd71fc207254820a2c4a85aeb0b2041494f8bf1f8cd30f11394223cf8a82995804957876e9fa71163506b4e5b8c8fa4db1b95d3e8c5c5fb5ae737529060e710a93e9718dd3e29418e948fe9201f8dfb3a22cf22e8941d427b54940bb47c1b5ebab27698f19fd97f3368695487f64fc1191ee301b200432e54",
         "951a475ae4098ba8ddf5976f46ade5a430e6be03827537ca8cef115350357cfe0ed686fe5ad7e4ffd00daadf913cb17d68e1857a9c2d97328e41432dd60df10eb04ab31e809ae9ece95686f1e6abbfd49c46f261b1d247824f0f90991ae4d4497b4dd6db2910c2751524a92ef89459a40a6d859a78f460b53ed653f984e92aea"],
        ["0039095355670e07dda6f87c7f78afe7e1036fd75330f07114f124143452690c8b725fe0d96de8b613e0329258e17a39e5e911381901a92df3cd42271fab33ab1d938bf60073ac1454dea6acbf20e6a409f7dc23f88650eb539213733d461e5ad9a950da1dfcee71da941d9ab5033ebefa1be1f3a132def4c4f1670238855c11",
         "32de541ae47be8346b69474ad0ea9dd77a841f27d4057bbd58ab52c8ab979dd998214d4dba93280cfba9701f9f1b7b9d6cf46156f28003a0ef3cc8cfb41b8a834c935dbfae19fd6f468dc19ede9cfeea56a15e41709a8e161478f02e7917e609cb3e3136bcb51983a53721e7ade97ae3da32ad2e46ca5e7cd2981801492aeeaf"],
        ["00adeb4ca9d9bd846eda1e23de5ce1d877c3cb18f5aa0db99b74bbd3fa18e529c5d0756eaa32f2180c103bea6d1cc3e4df8efdd4380a8ed47e49a778618ca1265d16950748871f55985a3f057602e95691e62ac9f0b89d6f0245e763d1898a2e9f1f35e8a6543d3eae7c43257f2d7b1013a5d9045e777360bc5ac38de34dbc83",
         "0265c596781e59d6a0a3dcdb05b5a9317771b07475e6f359c0681f62b6ae1902124d1018c6d80b75bd69d1c884dc7c1ae2bb2d1d4d2d12e1e5593e3b4e851d54234e5192d25f1078a524a2419d417dea6839208c77a8b3e185849e47ff35308712fd5a6479a04490aa34bfe84997621e5fe7b10a38d580420a5d25020bd995b8"],
    ];

    print("  1024/nopad");
    rsa_cipher_test(rsaciph, rsaciphpubkey, rsaciphprivkey, rsaciphvector, true);
    
   
    // --- 1024/pkcs1 ---
    rsaciph = new JSUCrypt.cipher.RSA(JSUCrypt.padder.PKCS1_V1_5);
    rsaciphpubkey = new JSUCrypt.key.RSAPublicKey(1024, 
                                         "00010001",
                                         "9C1C97BBDFBBA3531BD6CFCC068E8888D2CEF6D6A4D002C21CE4F5B33A1C2D2278BA25D196DF1F55B2AA4C4F2454C02F59A99BD82C68ECBE673399AD7084C31C501437A39973AC8E2BBFA18FF0D41E8C8B48C5DBE3D02FF08A4A6CDC1D9F0DD5C163058C8286954A9339A6A53BE498C584A263676341FB033AFD3A0BDDDD13E3");
    rsaciphprivkey = new JSUCrypt.key.RSAPrivateKey(1024,
                                           "238FBBDCD745761A0B806E8B8A7ED3895F8437E4835CC31416E2ED396BA6597DBDC4A1B2D1CC77E5DCB24079D2CBDF8FA9BC223D2738AB9D6002F821F33CBAF9100BFE580EC68715CCAF86A12CF73AEE60804A6C8F42C58B1B717245BF110205C9FE6B876AF727156676BD730C43952CE530F1CF2E27F6ABC4D60F047DCCDA91",
                                           "9C1C97BBDFBBA3531BD6CFCC068E8888D2CEF6D6A4D002C21CE4F5B33A1C2D2278BA25D196DF1F55B2AA4C4F2454C02F59A99BD82C68ECBE673399AD7084C31C501437A39973AC8E2BBFA18FF0D41E8C8B48C5DBE3D02FF08A4A6CDC1D9F0DD5C163058C8286954A9339A6A53BE498C584A263676341FB033AFD3A0BDDDD13E3");

    rsaciphvector = [
        ["006431296486ed9cd71fc207254820a2c4a85aeb0b2041494f8bf1f8cd30f11394223cf8a82995804957876e9fa71163506b4e5b8c8fa4db1b95d3e8c5c5fb5ae737529060e710a93e9718dd3e29418e948fe9201f8dfb3a22cf22e8941d427b54940bb47c1b5ebab27698f19fd97f3368695487f6",
         "22e85a5ef735985c8043dc48f93c4314cb12799d3d51049bc986a9d8f65dbd7190a5fe653482c639eb1d1c8a46f8374c87762911896bf21d6dca4e854d60600986d5f06d1f9ab908275eb2ffaf9a9929831bbdac9e9956c2bfd44c044c2bb972bb65a21bdf901e0d4856a219d3f1b7709ddce003679ef573b9be4e007877dbf0"],
        ["0039095355670e07dda6f87c7f78afe7e1036fd75330f07114f124143452690c8b725fe0d96de8b613e0329258e17a39e5e911381901a92df3cd42271fab33ab1d938bf60073ac1454dea6acbf20e6a409f7dc23f88650eb539213733d461e5ad9a950da1dfcee71da941d9a",
         "532b60c8355965d3e032467d7ae4b91adfa60765e8d51710ef0b761a88b0827268f0979fda1c29494fff716272dbc0817a84ae5d5694780b135fb2644c80ac9e3d76d7380c32fe6134b2fb746c75ec16ca485b690a9afee673b3de24cecb5d03f57c630946b73ad28944c7605ea0fb0a2d4bc1cc8eaf88a35fa6b14a9dddbc55"],
        ["00adeb4ca9d9bd846eda1e23de5ce1d877c3cb18f5aa0db99b74bbd3fa18e529c5d0756eaa32f2180c103bea6d1cc3e4df8efdd4380a8ed47e49a778618ca1265d16950748871f55985a3f057602e95691e62ac9f0b89d6f0245e763d1898a2e9f1f",
         "49044b8a4dc221fc259831a8350c43991d4924abbbae390698c5385d01f923da140b8d64deaa191b8c0d8db38702808530a9a62570b4cc64ecc8a9d4bbac1a43b3c8848d06bc89a3ea37ecd53d1ad98622649dec4992a6ebe03c0e153f7940013de72dd51d6738c0553d6e3f8424541ae87a393dc1f47b87920d0e08fe2d46a2"],
    ];

    print("  1024/pkcs1");
//    rsa_cipher_test(rsaciph, rsaciphpubkey, rsaciphprivkey, rsaciphvector, false);
}


function rsa_sign_test(signature, pubkey, privkey, vec) {
   var i, ct,pt,blk;

    //test sign
    print("    sign/finalize");
    for (i = 0; i<vec.length; i++) {
        signature.init(privkey, JSUCrypt.signature.MODE_SIGN);
        ct = signature.sign(vec[i][0]);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {            
            print("      "+i+" : NOK");
            print("        "+vec[i][1]);
            print("        "+ct);
            hasFailure = true;            
        }
    }
    print("    sign/update");
    for (i = 0; i<vec.length; i++) {
        signature.init(privkey, JSUCrypt.signature.MODE_SIGN);
        ct = [];
        pt = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = pt.slice(0,5);
            pt = pt.slice(5);
            signature.update(blk);
        }
        ct = signature.sign(pt);
        ct = JSUCrypt.utils.byteArrayToHexStr(ct);
        if (vec[i][1].equals(ct)) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            print("        "+vec[i][1]);
            print("        "+ct);
            hasFailure = true;
        }
    }

    //test verify
    print("    verify/finalize");
    for (i = 0; i<vec.length; i++) {
        signature.init(pubkey, JSUCrypt.signature.MODE_VERIFY);
        pt = signature.verify(vec[i][0], vec[i][1]);
        if (pt) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }
    print("    verify/update");
    for (i = 0; i<vec.length; i++) {
        signature.init(pubkey, JSUCrypt.signature.MODE_VERIFY);
        pt = [];
        ct = JSUCrypt.utils.anyToByteArray(vec[i][0]);
        while (pt.length>5) {
            blk = ct.slice(0,5);
            ct = ct.slice(5);
            pt = pt.concat(signature.update(blk));
        }
        pt = pt.concat(signature.verify(ct, vec[i][1]));
       
        if (pt) {
            print("      "+i+" : OK");
        } else {
            print("      "+i+" : NOK");
            hasFailure = true;
        }
    }
}

if (test_sign_rsa) {
    var rsasighasher,rsasig;  
    var rsapubkey, rsaprivkey, rsacrtkey;
    var vector;

    print("====================================================================");
    print("                        RSA SIGNATURE TESTING                       ");
    print("====================================================================");
    
    // --- 1024/SHA1 ---
    rsasighasher = new JSUCrypt.hash.SHA1();    
    rsasig = new JSUCrypt.signature.RSA(rsasighasher, JSUCrypt.padder.PKCS1_V1_5);
    rsapubkey = new JSUCrypt.key.RSAPublicKey(1024, 
                                         "00010001",
                                         "ADC469845841E0F2D46CADFF23E24F3E81C0C64F11721B9DAF18E5B74FA56876B12E4AFD420A0CC70B88FE07010E8D2E302A12DD15A2B20BEBAA95C04A45A22D236698C142121C8729E22382D9E8AA70DEC9E9AFD17A9912E7666BDEA67EBD6D2C70B6B9FE3B58D109F50CC740FB46C648AAC1CFD9FC3B7AEE86BA32B6DEBC93");
    rsaprivkey = new JSUCrypt.key.RSAPrivateKey(1024,
                                           "7CFFD587C6955D64513AFCCF94D8AF789F8E35199BCB21E2849ABC64E97E6B6F3675BEAC005D8A638500BEFBFADEA4E09CF5272CB2EB9E78C4C6A982F1EAB585E2E7102E8F8B2987088F0C66FEBBE9EA6ECC5187CC3E0C4D748F62F1A0B7C8DFAB5BCE707F81E401E7F41BEEED6C5BC3776221EAB5EAE1CC890A5AE8E47881C1",
                                           "ADC469845841E0F2D46CADFF23E24F3E81C0C64F11721B9DAF18E5B74FA56876B12E4AFD420A0CC70B88FE07010E8D2E302A12DD15A2B20BEBAA95C04A45A22D236698C142121C8729E22382D9E8AA70DEC9E9AFD17A9912E7666BDEA67EBD6D2C70B6B9FE3B58D109F50CC740FB46C648AAC1CFD9FC3B7AEE86BA32B6DEBC93");

    vector = [
        ["",
         "649bf31dc6abe3d21d005f4cd2a41abb8640f9fb04c84ec35a42390bf669a87c67c34b1059e7d3512ec724381a95e5bfa9901a47be8b7a921496ab4772821732faad65ccf503b66f70711f3f267450d897f50042867d0f3645e1938a30c20220c66bef02e4a54e1c251042d203dadf38e1fc0da8035d10456c3eced21d2c74f4"],
        ["d71fc207254820a2c4a85aeb0b2041494f8bf1f8cd30f11394223cf8a82995804957876e9fa71163506b4e5b8c8fa4db1b95d3e8c5c5fb5ae737529060e710a93e9718dd3e29418e948fe9201f8dfb3a22cf22e8941d427b54940bb47c1b5ebab27698f19fd97f3368695487f64fc1191ee301b200432e54d739095355670e07dda6f87c7f78afe7e1036fd75330f07114f124143452690c8b725fe0d96de8b613e0329258e17a39e5e911381901a92df3cd42271fab33ab1d938bf60073ac1454dea6acbf20e6a409f7dc23f88650eb539213733d461e5ad9a950da1dfcee71da941d9ab5033ebefa1be1f3a132def4c4f1670238855c112fadeb4ca9d9bd846eda1e23de5ce1d877c3cb18f5aa0db99b74bbd3fa18e529c5d0756eaa32f2180c103bea6d1cc3e4df8efdd4380a8ed47e49a778618ca1265d16950748871f55985a3f057602e95691e62ac9f0b89d6f0245e763d1898a2e9f1f35e8a6543d3eae7c43257f2d7b1013a5d9045e777360bc5ac38de34dbc836cf16b1346a851f4249519a3c294b3d53a8dd998044cf8c0a7bb4d8a09090d75fb78884120da35456f4fe831e39c061d29e0b52d2cadedd3693a5e72446be73fe47080044ab549b90432eae8cef005f7d0bb24fd6811d0d14b2e438f9a2bce7e9b4e82e504cc9e08fe88f0cc78f6c349b1e74619f816eb43452ed3df59a15df4f0dfd9f4ab77fca9ffed7578e338c1941f07ad171d985b62c72e4120cf9e15bf7eeeb32966b0d3659d48dd80819e14a0a5c1b8c35a132521416741100556d0834583adab338010d0c8ee50498c64ea3226a2f580b51aa1f681e2068739d60a7e5ab7298d37395e0027ae49b4",
         "822d6529b0cd37cb9795aec4c1afe1381bcd5c59bd29ca0d89ad9581d6d1386b9c3127d4ca242b5d9fcab679c2a779ff1e207b47fd568599d41817117b4f4951e99230a796cfd6430ab5ee0e8e33d32f339166bb1c5923931a388c1f5a1b67b931dd4135d1ee6284e848d82f0262cc95f3ad1bfc0e933dd3f9df2c1ce4ac4ca5"],
        ["1aa3569b4877cdce36c227402ef19647e80acc38dd99e919d24722e1f8b32d125683ae9ffb7b6d313e95716c8608b46e1280a7ef1a9008ecd82acdd0defbe3347e91d3790c41aa4ad61cb75c246bcb36eb722505022df1da57bfab35ba8e6a381f3db22b7e5c7654782db19c987cd283eef789f0247acb7c3976b1f3041b2c2359de4ed73ac42cb3f1dd4f8959220d471996373e1002ba4a786b3d7c87699fe047eeb782b2e335a4c0842d19a63a60c0d098fee19ab82b1323688faad22f8a191d429bcf25d073e655a1fffbdb60bbacf8b98d9271b8a59520353ff264ca0c810ca7503178c417cd6517c8407784ec6f3d7901af31a74452dc8344404d50c159f8118b70d5a23d3ab9057b3089679f",
         "30cb5b9a33d119d585570161a8b86db54ba4b02fd7b8210baeae9bbe6f7c837f00110e6fefe0c7e73bb241a319f6d48d112be9331d07cb7a83ff16f959214c98f226f0a5856c37983ec6772b8bbd27dffe2766378628714caa12917305788be016f526fe237ef62531191c5fa36cf3ad9945bcc67763dfb491a39401755c09ac"],
    ];

    print("  1024/sha1/pkcs1");
    rsa_sign_test(rsasig, rsapubkey, rsaprivkey, vector);

}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
//                                    HASH
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
if (test_hash) {
    print("====================================================================");
    print("                            HASH TESTING                            ");
    print("====================================================================");
    hasFailure = false;
    var inputs = [
        "",
        "abc",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
    ];

    var sha1_answers = [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "281990516def979bcf61c25b05e068e0ffab4827",
        "f2090afe4177d6f288072a474804327d0f481ada"
    ];

    var sha224_answers = [
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "54f109ed7418ae9d9a212473672cdcbc4771af5f7d6bd2d186d409fb",
        "92d2aa4e53e2120ac38d0afabf59d316d2632f8be35a4059dc005e8d"
    ];
    var sha256_answers = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "690c197164b3bafc3a2b94834a9607edbec7b32bb77e33c115f7a3e03fbc90a7",
        "2f617f4789492c761be62ea114a24952fd681333e9838f2fa85b9d104e326a47"
    ];
    var ripemd160_answers = [
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "9ede1cc6e629f72b99aa1278e95c38dbf2a67f3b",
        "f700135102741e9efd12df1085be0d631ebcbc06"
    ];



    function test(name, hash, answers) {
        print("*** Test "+name);
        var i,r, blk;
        for (i = 0; i<inputs.length;i++) {
            hash.reset();
            blk = JSUCrypt.utils.strToByteArray(inputs[i]);
            r = hash.finalize(blk);
            r = JSUCrypt.utils.byteArrayToHexStr(r);
            if (answers[i].equals(r)) {
                print("    "+i+" : OK");
            } else {
                print("    "+i+" : NOK");
                print("   exp: "+answers[i]);
                print("   got: "+r);
                hasFailure = true;
            }
        }
        hash.reset();
        blk = JSUCrypt.utils.strToByteArray(inputs[inputs.length-1]);    
        while (blk.length > 11) {
            var d = blk.slice(0,11);
            hash.update(d);
            blk = blk.slice(11);
        }
        r = hash.finalize(blk);
        r = JSUCrypt.utils.byteArrayToHexStr(r);
        if (answers[inputs.length-1].equals(r)) {
            print("    "+i+" : OK");
        } else {
            print("    "+i+" : NOK");
            print("   exp: "+answers[inputs.length-1]);
            print("   got: "+r);
            hasFailure = true;
        }

        report(name,hasFailure);
        hasFailure = false;
    }


    test("SHA1",      new JSUCrypt.hash.SHA1(),      sha1_answers);
    test("SHA224",    new JSUCrypt.hash.SHA224(),    sha224_answers);
    test("SHA256",    new JSUCrypt.hash.SHA256(),    sha256_answers);
    test("RIPEMD160", new JSUCrypt.hash.RIPEMD160(), ripemd160_answers);

}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
//                                    ECC
// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
if (test_ecfp) {
    print("====================================================================");
    print("                       ECFP  TESTING                      ");
    print("====================================================================");

    print("  uncompressed form");
    var d =  JSUCrypt.ECFp.getEcDomainByName("secp256k1");
    var p = new JSUCrypt.ECFp.AffinePoint("edc8530038d1186b9054acb75aef1419e78ae29b7ee86d42d2dc675504367421",
                                        "70b4c38a9eb95587f88c3ca33ae760cc0118dcc453d25c1653a54d920f1debe5",
                                        d.curve);
    var ex = "04edc8530038d1186b9054acb75aef1419e78ae29b7ee86d42d2dc67550436742170b4c38a9eb95587f88c3ca33ae760cc0118dcc453d25c1653a54d920f1debe5";
    var u = p.getUncompressedForm();
    u = JSUCrypt.utils.byteArrayToHexStr(u);
    if (u.equals("04edc8530038d1186b9054acb75aef1419e78ae29b7ee86d42d2dc67550436742170b4c38a9eb95587f88c3ca33ae760cc0118dcc453d25c1653a54d920f1debe5")) {
      print("      affine : OK");
    } else {
        print("    affine : NOK");
        print("     expect:"+ex);
        print("          u:"+u);
        hasFailure = true;
    }
    report("ECFP/uncompressed form", hasFailure);
    hasFailure = false;
}

if (test_ka_ecdh) {
    print("====================================================================");
    print("                       ECDH  TESTING                      ");
    print("====================================================================");

    print(" ---                      ECDH/SVDP                            ---*/");
    var ecdhpubkey,ecdhprivkey,ecdhdomain;
    var otherpoint;
    //secp256k1
    ecdhdomain =  JSUCrypt.ECFp.getEcDomainByName("secp256k1");
    ecdhprivkey = new JSUCrypt.key.EcFpPrivateKey(
        256, ecdhdomain, 
        "fb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5"
    );

    ecdhpubkey = new JSUCrypt.key.EcFpPublicKey(
        256, ecdhdomain, 
        new JSUCrypt.ECFp.AffinePoint("65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00",
                                    "e6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f")
    );
    //other point
    otherpoint = new JSUCrypt.ECFp.AffinePoint("edc8530038d1186b9054acb75aef1419e78ae29b7ee86d42d2dc675504367421",
                                             "70b4c38a9eb95587f88c3ca33ae760cc0118dcc453d25c1653a54d920f1debe5",
                                             ecdhdomain.curve);
    //secret
    var expectedSecret = "9907804058351d5249aa9734c8fafff2291bc072105d196fa7052b77ffed1fe7";


    //test
    print("  ECDH/SVDP/secp256k1");
    i = 0;
    var ecdh = new JSUCrypt.keyagreement.ECDH_SVDP(ecdhprivkey);
    var secret = ecdh.generate(otherpoint);
    secret = JSUCrypt.utils.byteArrayToHexStr(secret);
    if (secret.equals(expectedSecret))  {
        print("      "+i+" : OK");
    } else {
        print("      "+i+" : NOK");
        hasFailure = true;
    }
    report("SVDP/secp256k1 ", hasFailure);
    hasFailure = false;
}

if (test_sign_ecdsa) {
    print("====================================================================");
    print("                       ECDSA SIGNATURE TESTING                      ");
    print("====================================================================");

    print(" ---                      ECDSA/SHA1                            ---*/");
    var pubkey,privkey,domain,ver;
    var sha  = new  JSUCrypt.hash.SHA1();
    var ecsig = new JSUCrypt.signature.ECDSA(sha);
    var input,sig, wrongsig;

    //secp256k1
    domain =  JSUCrypt.ECFp.getEcDomainByName("secp256k1");
    privkey = new JSUCrypt.key.EcFpPrivateKey(
        256, domain, 
        "f028458b39af92fea938486ecc49562d0e7731b53d9b25e2701183e4f2adc991");

    pubkey = new JSUCrypt.key.EcFpPublicKey(
        256, domain, 
        new JSUCrypt.ECFp.AffinePoint("81bc1f9486564d3d57a305e8f9067df2a7e1f007d4af4fed085aca139c6b9c7a",
                                    "8e3f35e4d7fb27a56a3f35d34c8c2b27cd1d266d5294df131bf3c1cbc39f5a91"));

    input    = "1c0a8602c503a6bd48e1e85840f514e65853";
    sig      = "3046022100d8212568c7ca771ac131250ca63922c8eaec3185f00a6863274e0c55c031161e022100c236d64724b6b8b7d8d45ddbfeed8fc94a0d34d9294c6a029e909d695474f9a3";
    wrongsig = "3046022100d8212568c7ca771ac130250ca63922c8eaec3185f00a6863274e0c55c031161e022100c236d64724b6b8b7d8d45ddbfeed8fc94a0d34d9294c6a029e909d695474f9a3";

    ecsig.init(pubkey,  JSUCrypt.signature.MODE_VERIFY);
    ver = ecsig.verify(input, sig);
    print("secp256k1/trusted_sig: " + (ver?"OK":"NOK"));
    if (!ver) hasFailure = true;

    ecsig.init(pubkey,  JSUCrypt.signature.MODE_VERIFY);
    ver = ecsig.verify(input, wrongsig);
    print("secp256k1/trusted_wrong_sig: " + (ver?"NOK":"OK"));
    if (ver) hasFailure = true;
    
    //secp192r1
    domain =  JSUCrypt.ECFp.getEcDomainByName("secp192r1");
    privkey = new JSUCrypt.key.EcFpPrivateKey(
        256, domain, 
        "98de9c2529ad3498287c84c5fbe94f1c1ffc0ed6e62f1b88");
    pubkey = new JSUCrypt.key.EcFpPublicKey(
        256, domain, 
        new JSUCrypt.ECFp.AffinePoint("c8a20e0b34dc0c3f96e5a435fac917042e21c9a5c24815a3",
                                    "2fce93fb27837fea1147f38ebcf9b297f8012df7f91a4838"));

    input     = "01327d9184ae9b1e33495b10ce4f0c879a8f90a02c16da3e5b3f331caf8d9b4daa993f491a02b12970a8a74ab3a8d2c4b8d49e5b633bbbf8c8ac7cdcb6437f029f832fe9ce0cc3d1224a7f514c7be8806675979394f0fb8bd083d39a31364f1ea42b4f7df6eb7b7a1cff0428dbb3c8157c49573d9ed99d0515022488133224e3de8daf8cc9487371967fd2690ef8acc4b5ce7be4251e780883af91c6edcfc287e85a6c5aac328ab97f13ba1233dd914bd72277d811e6635934fdf38c699f69cfe63f69014ccbb896f697a4fa222c4e2557370ec1cf8baf8f9f6426cfa20e15483a07d12beb1dbbd56704971ea708e3ed1512203f2f1f302f89ff7dd9e7c32ddd8bb591e76b1ac714818fbf5e3c78c5d5f8d36fa04e2ea64d5bd0fcb461fa9e1b21afdb88252e106670825ea3d8dc73bb707f67b62b99152347c89edea776cbedb721e01c15353e6ef55899fa";
    sig      = "3035021834411c8e628ba3e26773a3ce9858f9b45952b1561a913b2f021900dc7c625580a226200476fdd9a3defe65afa9eaa26bc71449";
    wrongsig = "3035021834411c8e628ba3e26773a3ce9858f9b45952b1561a913b2f021900dc7c625580a226200476fdd9a4defe65afa9eaa26bc71449";

    ecsig.init(pubkey,  JSUCrypt.signature.MODE_VERIFY);
    ver = ecsig.verify(input, sig);
    print("secp192r1/trusted_sig: " + (ver?"OK":"NOK"));
    if (!ver) hasFailure = true;
    ecsig.init(pubkey,  JSUCrypt.signature.MODE_VERIFY);
    ver = ecsig.verify(input, wrongsig);
    print("secp192r1/trusted_wrong_sig: " + (ver?"NOK":"OK"));
    if (ver) hasFailure = true;

    //auto verif
    var domains = ["secp256k1","secp256r1", "secp192k1", "secp192r1", "secp160k1", "secp160r1"];
    for (var i = 0; i<domains.length; i++) {
        domain =  JSUCrypt.ECFp.getEcDomainByName(domains[i]);
        [pubkey, privkey] =  JSUCrypt.key.generateECFpPair(256, domain);
        ecsig.init(privkey,  JSUCrypt.signature.MODE_SIGN);
        sig = ecsig.sign("abc");
        ecsig.init(pubkey,  JSUCrypt.signature.MODE_VERIFY);
        ver = ecsig.verify("abc", sig);
        print(domains[i]+"/auto_sig_with_key_gen: " + (ver?"OK":"NOK"));
        if (!ver) hasFailure = true;
    }

    report("Sign ECDSA/SHA1", hasFailure);
    hasFailure = false;

}







//************************************************************************//
printReport();