// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./verifier.sol";
import "./SolRsaVerify.sol";
import "./VerifierInfo.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

contract DKIMVerifier is Verifier {
    
    constructor() {}

    function verifier(
        address publicKey,
        bytes memory modulus,
        VerifierInfo calldata info
    ) external view returns (bool)  {
        uint[] memory input = getInput(info.hmua, info.bh, info.base);
        //ZKP Verifier
        if (!verifyProof(info.a, info.b, info.c, input)) {
            return false;
        }
        //bh(bytes) == base64(sha1/sha256(Canon-body))
        if (!equalBase64(info.bh, info.body)) {
            return false;
        }
        //Operation ∈ Canon-body
        if (!containsAddress(publicKey, info.body)) {
            return false;
        }
        //b == RSA(base)
        if (!sha256Verify(info.base, info.rb, info.e, modulus)) {
            return false;
        }
        return true;
    }

    function getInput(
        bytes32 hmua,
        bytes memory bh,
        bytes32 base
    ) public pure returns (uint[] memory) {
        require(bh.length == 44);
        uint[] memory output = new uint[](108);
        uint index = 0;
        for (uint i = 0; i < 32; i++) {
            output[index++] = uint(uint8(hmua[i]));
        }
        for (uint i = 0; i < bh.length; i++) {
            output[index++] = uint(uint8(bh[i]));
        }
        for (uint i = 0; i < 32; i++) {
            output[index++] = uint(uint8(base[i]));
        }
        return output;
    }

    function sha256Verify(bytes32 base, bytes memory rb, bytes memory e, bytes memory modulus) public view returns (bool) {
        uint result = SolRsaVerify.pkcs1Sha256Verify(base, rb, e, modulus);
        return result == 0;
    }

    function equalBase64(bytes memory bh, bytes memory body) public pure returns (bool) {
        return keccak256(bh) == keccak256(bytes(Base64.encode(abi.encodePacked(sha256(body)))));
    }


    function toAsciiBytes(address x) internal pure returns (bytes memory) {
        bytes memory s = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2*i] = char(hi);
            s[2*i+1] = char(lo);            
        }
        return s;
    }

    function char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    function containsAddress(address publicKey, bytes memory body) public pure returns (bool) {
        return contains(toAsciiBytes(publicKey), body);
    }

    function contains(bytes memory whatBytes, bytes memory whereBytes) public pure returns (bool) {
        if (whereBytes.length < whatBytes.length) {
            return false;
        }

        bool found = false;
        for (uint i = 0; i <= whereBytes.length - whatBytes.length; i++) {
            bool flag = true;
            for (uint j = 0; j < whatBytes.length; j++)
                if (whereBytes [i + j] != whatBytes [j]) {
                    flag = false;
                    break;
                }
            if (flag) {
                found = true;
                break;
            }
        }
        return found;
    }
}
