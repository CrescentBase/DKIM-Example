pragma circom 2.0.3;

template Concat(maxLen) {
    signal input in1[maxLen];
    signal input in2[maxLen];
    signal input in1_len;

    signal output out[maxLen];

    var mergeIndex = 0;
    var mergeArr[maxLen];

    for (var i = 0; i < maxLen; i++) {
        if (i >= in1_len) {
            mergeArr[i] = in2[mergeIndex];
            mergeIndex = mergeIndex + 1;
        } else {
            mergeArr[i] = in1[i];
        }
    }

    for (var i = 0; i < maxLen; i++){
        out[i] <-- mergeArr[i];
    }
}