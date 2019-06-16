const bech32 = require('./crypto/bech32');
const base58 = require('./crypto/base58');

const cryptoUtils = require('./crypto/utils');

const DEFAULT_NETWORK_TYPE = 'prod';

function getDecoded(address) {
    // non-sapling
    try {
        return base58.decode(address);
    } catch (e) {
        // try for sapling, do not return null...yet
        //return null;
    }
    // sapling, bech32 decode
    if (address.slice(0,2) == 'zs') {
        let decoded;
        try {
            decoded = bech32.decode(address);
        } catch (error) {
            return null;
        }
        // ConvertedSaplingPaymentAddressSize == decoded.data.length == 69
        // https://github.com/zcash/zcash/blob/master/src/key_io.cpp#L168
        if (decoded && decoded.data && decoded.data.length == 69)
            return decoded;
    }
    return null;
}

function getChecksum(hashFunction, payload) {
    return cryptoUtils.sha256Checksum(payload);
}

function getAddressType(address, currency) {
    currency = currency || {};
    
    let expectedLength = currency.expectedLength || 25;
    let hashFunction = currency.hashFunction || 'sha256';
    let decoded = getDecoded(address);
    if (decoded) {
        // sapling bech32 decode
        if (decoded.hrp) {
            return decoded.hrp;
        }
        // non-sapling base58 decode
        let length = decoded.length;
        if (length !== expectedLength) {
            return null;
        }
        let checksum = cryptoUtils.toHex(decoded.slice(length - 4, length)),
            body = cryptoUtils.toHex(decoded.slice(0, length - 4)),
            goodChecksum = getChecksum(hashFunction, body);

        return checksum === goodChecksum ? cryptoUtils.toHex(decoded.slice(0, expectedLength - 24)) : null;
    }
    return null;
}

function isValidZCashAddress(address, currency, networkType) {
    networkType = networkType || DEFAULT_NETWORK_TYPE;

    // valid chars test
    if (/^[a-zA-Z0-9]+/g.test() === false) {
        return false;
    }
    
    let correctAddressTypes;
    let addressType = getAddressType(address, currency);

    if (addressType) {
        correctAddressTypes = currency.addressTypes[networkType];
        if (correctAddressTypes)
            return correctAddressTypes.indexOf(addressType) >= 0;
    }

    return false;
}

module.exports = {
    isValidAddress: function (address, currency, networkType) {
        return isValidZCashAddress(address, currency, networkType);
    }
};
