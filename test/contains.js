const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
// const wasm_tester = require("circom_tester").wasm;
const wasm_tester = require("./tester.js");
const assert = chai.assert;

const {bufferToBitArray, bitArrayToBuffer, strToBytes} = require("./helpers/utils");

function msgToBitsSHA(msg, blocks) {
    let inn = bufferToBitArray(Buffer.from(msg));
    // console.log('inn = ', inn);
    const overall_len = blocks * 512;
    const add_bits = overall_len - inn.length;
    inn = inn.concat(Array(add_bits).fill(0));
    // console.log('inn = ', inn);
    return inn;
}

function msgToBits(msg) {
    let inn = bufferToBitArray(Buffer.from(msg));
    return inn;
}

var cir;

async function compile() {
    console.time("Compile");
    const p = path.join(__dirname, `../circuits/contains_test.circom`)
    const cir = await wasm_tester(p);
    console.log(cir);
    console.timeEnd("Compile");

    return cir;
}


async function anotherTest(cir) {
    const MAX_LEN = 1024;     // in1 and in2 max_len 1024 byte

    var preimageMsg = "090b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1wawqwerqwer";
    var msgBytes = strToBytes(preimageMsg, MAX_LEN);
    assert(msgBytes.length == MAX_LEN, "Illegal msg length");

    var proimageBh = "090b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1";
    var bhBytes = strToBytes(proimageBh, MAX_LEN); // len of bh=sha256(can-body) is 256
    assert(bhBytes.length == MAX_LEN, "Illegal bhBits length");

    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "in1":msgBytes, "in2":bhBytes, "in1_len":preimageMsg.length, "in2_len":proimageBh.length }, true);
    console.timeEnd("Generating witness");
}

async function wrongTest(cir) {
    const MAX_LEN = 1024;     // in1 and in2 max_len 1024 byte

    var preimageMsg = "190b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1wawqwerqwer";
    var msgBytes = strToBytes(preimageMsg, MAX_LEN);
    assert(msgBytes.length == MAX_LEN, "Illegal msg length");

    var proimageBh = "090b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1";
    var bhBytes = strToBytes(proimageBh, MAX_LEN); // len of bh=sha256(can-body) is 256
    assert(bhBytes.length == MAX_LEN, "Illegal bhBits length");

    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "in1":msgBytes, "in2":bhBytes, "in1_len":preimageMsg.length, "in2_len":proimageBh.length }, true);
    console.timeEnd("Generating witness");
}


describe("Contains", function () {
    this.timeout(1000000000);

    it ("Should compile", async () => {
        cir = await compile();
    });

    it ("Should accept", async () => {
        await anotherTest(cir);
    });

    it ("Should reject", async () => {
        await wrongTest(cir);
    });

    


});