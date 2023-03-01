const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
// const wasm_tester = require("./tester.js");
const wasm_tester = require("circom_tester").wasm;
const assert = chai.assert;
const fs = require("fs");


const {bufferToBitArray, bitArrayToBuffer} = require("./helpers/utils");

function msgToBitsSHA(msg, blocks) {
    let inn = bufferToBitArray(Buffer.from(msg));
    const overall_len = blocks * 512;
    const add_bits = overall_len - inn.length;
    inn = inn.concat(Array(add_bits).fill(0));
    return inn;
}

function msgToBits(msg) {
    let inn = bufferToBitArray(Buffer.from(msg));
    return inn;
}

var cir;

async function compile() {
    console.time("Compile");
    const p = path.join(__dirname, `../circuits/testDkim.circom`);
    const cir = await wasm_tester(p);
    console.timeEnd("Compile");
    return cir;
}





async function correctTest(cir) {
    const SHA256_LEN = 256;
    // console.log(Buffer.from(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')));
    // const HMUA = msgToBits(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')); // sha256(crescent)
    // const HMUA = msgToBits("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b"); // sha256(crescent)
    
    var HMUA = (Array(SHA256_LEN).fill(1));
    const base = msgToBits(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex'));// sha256(123456)
    console.log("base=",base.length);
    console.log("HMUA=",HMUA);

    const crescent = "crescent";
    const fromPlusSalt = msgToBitsSHA(crescent,16);
    const fromPlusSaltLen = crescent.length;
    console.time("Generating witness");
    const witness = await cir.calculateWitness({"HMUA": HMUA,"fromPlusSaltLen": 2}, true);
    // const witness = await cir.calculateWitness({"bh": [2,1,0],"msg": [1,1,3,4]}, true);

    console.timeEnd("Generating witness");

}

async function wrongTest(cir) {
    const msgLen = 8192;
    const bhLen = 2048;
    const SHA256_LEN = 256;

    var msgBits = msgToBitsSHA(Array(1024).fill(0),16);
    console.log("msgBits = ",msgBits);

    var bhBits = msgToBits(Array(SHA256_LEN).fill(1));
    console.log("bhBits = ",bhBits);

    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "bh":bhBits, "msg":msgBits }, true);
    console.timeEnd("Generating witness");
}


describe("testDkim", function () {
    this.timeout(1000000000);

    it ("Should compile", async () => {
        cir = await compile();
    });

    it ("Should accept", async () => {
        await correctTest(cir);
    });

    // it ("Should reject", async () => {
        // await wrongTest(cir);
    // });

    


});

