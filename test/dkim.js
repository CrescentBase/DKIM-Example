const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
const wasm_tester = require("./tester.js");
const assert = chai.assert;
const fs = require("fs");



const {bufferToBitArray, bitArrayToBuffer, sha256Pad, strToBytes} = require("./helpers/utils");
const { base64 } = require("ethers/lib/utils.js");

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

function shaHash(str) {
    return crypto.createHash("sha256").update(str).digest();
}

async function saveWitnessToLocal(input){
    const buff= await cir.witnessCalculator.calculateWTNSBin(input,0);
	fs.writeFile(path.join("../build_circuits/" + "witness.wtns"), buff, function(err) {
	    if (err) throw err;
	});
}

let cir;
async function compile() {
    console.time("Compile");
    const p = path.join(__dirname, `../circuits/dkim.circom`);
    const cir = await wasm_tester(p);
    console.timeEnd("Compile");
    return cir;
}

const BH_LEN = 44;
const BLOCK_LEN = 1024;
const SHA256_LEN_BYTES = 32;

function getInput(
        from = "dysquare@foxmail.com",
        salt = "f7089d74bf224cc21fb8191bafefe24d80709bf2e598d0e8dd9648e599cfe594",
        HMUA = strToBytes(shaHash(from + salt)),
        preimageOfBase = "from:\"=?gb18030?B?0rvCt8/ysbE=?=\" <dysquare@foxmail.com>\r\nto:\"=?gb18030?B?amx1dGVhY2hlcmx1bw==?=\" <jluteacherluo@gmail.com>\r\nsubject:signature test\r\ndate:Wed, 7 Dec 2022 21:20:35 +0800\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=foxmail.com; s=s201512; t=1670419235; bh=9RqYI6fxZOUZAYcxZV4SvznReZm2Mn7vMx5y5+asYAM=; h=From:To:Subject:Date; b=", //DKIM msg
        base = strToBytes(shaHash(preimageOfBase)),
        bh = "9RqYI6fxZOUZAYcxZV4SvznReZm2Mn7vMx5y5+asYAM="
    ){

    bh = strToBytes(Buffer.from((bh)))  
    const fromBytes = strToBytes(Buffer.from(from), BLOCK_LEN);
    const saltBytes = strToBytes(Buffer.from(salt), BLOCK_LEN);
    const msg = strToBytes(Buffer.from(preimageOfBase), BLOCK_LEN);
    // console.log("HMUA============", HMUA.length, HMUA, shaHash(from + salt).toString("hex"));
    // console.log("msg============", msg.length, preimageOfBase.length, base, msg);
    // console.log("bh============", bh.length, bh);
    
    assert(HMUA.length == SHA256_LEN_BYTES, "Illegal HMUA length");
    assert(bh.length == BH_LEN, "Illegal bhBits length");
    assert(base.length == SHA256_LEN_BYTES, "Illegal base length");
    assert(fromBytes.length == BLOCK_LEN, "Illegal fromBytes length");
    assert(saltBytes.length == BLOCK_LEN, "Illegal saltBytes length");
    assert(msg.length == BLOCK_LEN, "Illegal msg length");

    return { "HMUA": HMUA, "bh": bh, "base": base, "from":fromBytes, "salt":saltBytes, "msg":msg, "fromLen": from.length, "saltLen": salt.length, "msgLen":preimageOfBase.length};
}

async function testDkim(cir) {
    const input = getInput();
    console.time("Generating witness");    
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
    saveWitnessToLocal(input);
}

async function fakeFrom(cir) {
    const input = getInput(from = "hacker@foxmail.com");
    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
}

async function fakeBase(cir) {
    const input = getInput(base = "some fake base");
    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
}

async function fakeBh(cir) {
    const input = getInput(bh = "LLKlqPNZsYtmPlCdY9jkkHJiXHWi8ZGU7OfjmwPLfH4=");
    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
}

async function fakeHMUA(cir) {
    const input = getInput(HMUA = "some random fake string");
    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
}

async function fakeMsg(cir) {
    const input = getInput(preimageOfBase = "from:\"=?<fake@fake.com>\r\nto:\"=?gb18030?B?amx1dGVhY2hlcmx1bw==?=\" <jluteacherluo@gmail.com>\r\nsubject:signature test\r\ndate:Wed, 7 Dec 2022 21:20:35 +0800\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=foxmail.com; s=s201512; t=1670419235; bh=9RqYI6fxZOUZAYcxZV4SvznReZm2Mn7vMx5y5+asYAM=; h=From:To:Subject:Date; b=")
    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
}

describe("CRESCENT DKIM ZKP CIRCUIT", function () {
    this.timeout(1000000000);

    it ("Should compile", async () => {cir = await compile();});
    it ("Should pass testDkim", async () => {await testDkim(cir);});
    it ("Should reject fake from", async () => {await fakeFrom(cir);});
    it ("Should reject fake base", async () => {await fakeBase(cir);});
    it ("Should reject fake bh", async () => {await fakeBh(cir);});
    it ("Should reject fake HMUA", async () => {await fakeHMUA(cir);});
    it ("Should reject fake msg", async () => {await fakeMsg(cir);});
});

