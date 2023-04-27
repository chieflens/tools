const { Wallet, BigNumber, utils } = require("ethers");
const { ec, stark, hash, number, getChecksumAddress } = require("starknet");

const baseDerivationPath = "m/44'/9004'/0'/0";

function hashKeyWithIndex(key, index) {
    const payload = utils.concat([utils.arrayify(key), utils.arrayify(index)])
    const hash = utils.sha256(payload)
    return number.toBN(hash)
}

function grindKey(keySeed) {
    const keyValueLimit = ec.ec.n
    if (!keyValueLimit) {
        return keySeed
    }
    const sha256EcMaxDigest = number.toBN(
        "1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000",
        16,
    )
    const maxAllowedVal = sha256EcMaxDigest.sub(
        sha256EcMaxDigest.mod(keyValueLimit),
    )

    // Make sure the produced key is devided by the Stark EC order,
    // and falls within the range [0, maxAllowedVal).
    let i = 0
    let key
    do {
        key = hashKeyWithIndex(keySeed, i)
        i++
    } while (!key.lt(maxAllowedVal))

    return "0x" + key.umod(keyValueLimit).toString("hex")
}

function getPathForIndex(
    index,
    baseDerivationPath,
) {
    return `${baseDerivationPath}/${index}`
}

function getIndexForPath(path, baseDerivationPath) {
    if (!path.startsWith(baseDerivationPath)) {
        throw "path should begin with baseDerivationPath"
    }
    const index = path.substring(path.lastIndexOf("/") + 1)
    return parseInt(index)
}

function getStarkPair(words, index) {
    const secret = Wallet.fromMnemonic(words).privateKey;
    const masterNode = utils.HDNode.fromSeed(BigNumber.from(secret).toHexString());
    const path = getPathForIndex(index, baseDerivationPath ?? "");
    const childNode = masterNode.derivePath(path);
    const groundKey = grindKey(childNode.privateKey);
    const starkPair = ec.getKeyPair(groundKey);
    return starkPair;
};

//new Argent X account v0.2.3 :
const argentXproxyClassHash = "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918";
const argentXaccountClassHash = "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2";


function getArgentX(words, index) {
    // Generate public and private key pair.
    const starkKeyPubAX = ec.getStarkKey(getStarkPair(words, index));

    // Calculate future address of the ArgentX account
    const AXproxyConstructorCallData = stark.compileCalldata({
        implementation: argentXaccountClassHash,
        selector: hash.getSelectorFromName("initialize"),
        calldata: stark.compileCalldata({ signer: starkKeyPubAX, guardian: "0" }),
    });
    const AXcontractAddress = hash.calculateContractAddressFromHash(
        starkKeyPubAX,
        argentXproxyClassHash,
        AXproxyConstructorCallData,
        0
    );

    return getChecksumAddress(AXcontractAddress);
}

const words = utils.entropyToMnemonic(utils.randomBytes(32));
console.log(getArgentX(words, 0));