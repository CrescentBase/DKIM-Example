pragma circom 2.0.3;

include "../snark-jwt-verify/circomlib/circuits/bitify.circom";
include "./utils.circom";

template Sha256Pad(maxLen) {
    signal input in[maxLen];
    signal input in_len;

    signal output prepadOut[maxLen];
    signal output prepadLen;

    var tempLen = (in_len + 8) % 64;
    if (tempLen == 0) {
        tempLen = in_len + 8;
    } else {
        tempLen = (in_len + 8) + (64 - tempLen);
    }

    component ie1[maxLen];
    component ie2[maxLen];

    var lengthBytes[8];
    component num2Bits = Num2Bits(8 * 8);
    num2Bits.in <== in_len * 8;

    component bits2Num[8];
    for (var i = 0; i < 8; i++) {
        bits2Num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2Num[i].in[j] <== num2Bits.out[(7 - i) * 8 + j];
        }
        lengthBytes[i] = bits2Num[i].out;
    }


    for (var i = 0; i < maxLen; i++) {
        var tt;
        if (i == in_len) {
            tt = pow(2, 7);
        } else if (i >= tempLen - 8 && i < tempLen) {
            tt = lengthBytes[i + 8 - tempLen];
        } else {
            tt = in[i];
        }
        prepadOut[i] <-- tt;
    }
    prepadLen <-- tempLen;
}