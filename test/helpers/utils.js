
function bufferToBitArray(b) {
    const res = [];
    for (let i = 0; i < b.length; i++) {
        for (let j = 0; j < 8; j++) {
            res.push(b[i] >> (7 - j) & 1);
        }
    }
    return res;
}

function bitArrayToBuffer(a) {
    const len = Math.floor((a.length - 1) / 8) + 1;
    const b = new Buffer.alloc(len);

    for (let i = 0; i < a.length; i++) {
        const p = Math.floor(i / 8);
        b[p] = b[p] | (Number(a[i]) << (7 - (i % 8)));
    }
    return b;
}

function arrayChunk(array, chunk_size) {
    return Array(Math.ceil(array.length / chunk_size)).fill().map((_, index) => index * chunk_size).map(begin => array.slice(begin, begin + chunk_size));
}

function padMessage(bits) {
    const L = bits.length;
    const K = (512 + 448 - (L % 512 + 1)) % 512;

    bits = bits.concat([1]);
    if(K > 0) {
        bits = bits.concat(Array(K).fill(0));
    }
    bits = bits.concat(bufferToBitArray(Buffer.from(L.toString(16).padStart(16, '0'), 'hex')))
    
    return bits;
}

function int8toBytes(num) {
    let arr = new ArrayBuffer(1);
    let view = new DataView(arr);
    view.setUint8(0, num);
    return new Uint8Array(arr);
}

function int64toBytes(num) {
    let arr = new ArrayBuffer(8);
    let view = new DataView(arr);
    view.setInt32(4, num, false);
    return new Uint8Array(arr);
}
  
function mergeUInt8Arrays(a1, a2) {
    var mergedArray = new Uint8Array(a1.length + a2.length);
    mergedArray.set(a1);
    mergedArray.set(a2, a1.length);
    return mergedArray;
}


function sha256Pad(prepad, maxBytes) {

    let length_bits = prepad.length * 8;
    let length_bytes = int64toBytes(length_bits);
    prepad = mergeUInt8Arrays(prepad, int8toBytes(2 ** 7));
    while ((prepad.length * 8 + length_bytes.length * 8) % 512 !== 0) {
      prepad = mergeUInt8Arrays(prepad, int8toBytes(0));
    }
    prepad = mergeUInt8Arrays(prepad, length_bytes);
    let messageLen = prepad.length;
    while (prepad.length < maxBytes) {
      prepad = mergeUInt8Arrays(prepad, int64toBytes(0));
    }
  
    return [prepad, messageLen];
  }

function strToBytes(str, fill = 0) {
    const buf = Buffer.from(str);
    const arr = [];
    for (let i = 0; i < buf.length; i++) {
        arr.push(buf[i]);
    }
    const fillSpace = fill - buf.length;
    if (fillSpace > 0) {
        for (let i = 0;i < fillSpace; i++) {
            arr.push(0);
        }
    }
    return arr;
}

module.exports = {
    bufferToBitArray,
    bitArrayToBuffer,
    arrayChunk,
    padMessage,
    sha256Pad,
    int64toBytes,
    strToBytes
}