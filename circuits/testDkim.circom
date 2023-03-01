pragma circom 2.0.3;

include "./Sha256Var.circom";
include "./contains.circom";


template testDkim(BlockSpace) {
 

    // constant
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;

    // variable
    var maxBlockCount = pow(2, BlockSpace);
    var maxLen = BLOCK_LEN * maxBlockCount;
    
    // public statments
    signal input HMUA[SHA256_LEN]; // Hidden Mail User Agent = sha256(fromPlusSalt)


    // secret witnesses
    // signal input fromPlusSalt[maxLen];
    signal input fromPlusSaltLen;
    signal haha;

    0 === fromPlusSaltLen * fromPlusSaltLen;

    
    // HMUA Checker
    // component hmuaHasher = Sha256Var(BlockSpace);
    // hmuaHasher.len <== fromPlusSaltLen;
    // for (var i = 0; i < maxLen; i++) {
    //     hmuaHasher.in[i] <== fromPlusSalt[i];
    // }    

    // for (var i = 0; i < SHA256_LEN; i++) {
    //     hmuaHasher.out[i] === HMUA[i] ;
    //     log(hmuaHasher.out[i]);
    // }

    //     hmuaHasher.out[1] === HMUA[5] ;

}



// component main  {public [HMUA]} = testDkim(4);
component main = testDkim(4);




