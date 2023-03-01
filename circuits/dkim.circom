pragma circom 2.0.3;

include "./sha256Bytes.circom";
include "./contains.circom";
include "./concat.circom";
include "./sha256Pad.circom";


template dkim(BYTE_SIZE) {

    // constant
    var MAX_BYTES = 1024;
    var SHA256_LEN = 32;
    var BH_LEN = 44;
    
    // public statements
    signal input HMUA[SHA256_LEN]; // Hidden Mail User Agent = sha256(fromPlusSalt)
    signal input bh[BH_LEN]; // bh, bodyhash = sha256(Canon-body)
    signal input base[SHA256_LEN]; //base == sha256(msg)


    // secret witnesses
    signal input from[MAX_BYTES];
    signal input salt[MAX_BYTES];
    signal input msg[MAX_BYTES];
    signal input fromLen;
    signal input saltLen;
    signal input msgLen;

    // from + salt
    component concatArr = Concat(MAX_BYTES);
    concatArr.in1_len <== fromLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        concatArr.in1[i] <== from[i];
        concatArr.in2[i] <== salt[i];
    }

    // HMUA == sha(from + salt)
    component pad = Sha256Pad(MAX_BYTES);
    pad.in_len <== fromLen + saltLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        pad.in[i] <== concatArr.out[i];
    }

    component hmuaHasher = Sha256Bytes(MAX_BYTES);
    hmuaHasher.in_len_padded_bytes <== pad.prepadLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        hmuaHasher.in_padded[i] <== pad.prepadOut[i];
    }

    component hmuaB2n[SHA256_LEN];
    for (var i = 0; i < SHA256_LEN; i++) {
        hmuaB2n[i] = Bits2Num(BYTE_SIZE);
        for (var j = BYTE_SIZE - 1; j >= 0; j--) {
            hmuaB2n[i].in[BYTE_SIZE - 1 - j] <== hmuaHasher.out[i * BYTE_SIZE + j];
        }
        HMUA[i] === hmuaB2n[i].out;
    }

    // base == sha(msg)
    component msgPad = Sha256Pad(MAX_BYTES);
    msgPad.in_len <== msgLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        msgPad.in[i] <== msg[i];
    }

    component msgHasher = Sha256Bytes(MAX_BYTES);
    msgHasher.in_len_padded_bytes <== msgPad.prepadLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        msgHasher.in_padded[i] <== msgPad.prepadOut[i];
    }

    component msgB2n[SHA256_LEN];
    for (var i = 0; i < SHA256_LEN; i++) {
        msgB2n[i] = Bits2Num(BYTE_SIZE);
        for (var j = BYTE_SIZE - 1; j >= 0; j--) {
            msgB2n[i].in[BYTE_SIZE - 1 - j] <== msgHasher.out[i * BYTE_SIZE + j];
        }
        base[i] === msgB2n[i].out;
    }

    // bh ∈ msg checker
    component msgContainsBh = Contains(MAX_BYTES);
    msgContainsBh.in1_len <== msgLen;
    msgContainsBh.in2_len <== SHA256_LEN;
    for (var i = 0; i < MAX_BYTES; i++) {
        msgContainsBh.in1[i] <== msg[i];
        if (i < SHA256_LEN) {
            msgContainsBh.in2[i] <== bh[i];
        } else {
            msgContainsBh.in2[i] <== 0;
        }
    }

    // from ∈ msg checker
    component msgContainsFrom = Contains(MAX_BYTES);
    msgContainsFrom.in1_len <== msgLen;
    msgContainsFrom.in2_len <== fromLen;
    for (var i = 0; i < MAX_BYTES; i++) {
        msgContainsFrom.in1[i] <== msg[i];
        msgContainsFrom.in2[i] <== from[i];
    }
}

component main  {public [HMUA, bh, base]}= dkim(8);




