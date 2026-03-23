var should = require('should');
var bip39 = require('bip39');

var bip32Ed25519 = require('../index');
var eddsa = bip32Ed25519.eddsa;

describe('derive', function() {

    this.timeout(5 * 60 * 60 * 1000);

    it('general', function(done) {
        var seed = Buffer.from('e2282f95e0c16a0f2837553c9000c22c82d87e667b5ded17b26d15bdb60245f0e89067d412aa8c41caa4dfbbdcf8fd3095cb974c0104bc0a9309491f929681e1', 'hex');
        var xprv = bip32Ed25519.generateFromSeed(seed);
        console.log('xprv:', xprv.toString('hex'));

        var xpub = bip32Ed25519.toPublic(xprv);
        console.log('xpub:', xpub.toString('hex'));

        var total = 10000000;
        for (var i = 0; i < 100000; i++) {
            var index = parseInt(Math.random() * 100000);
            console.log('[' + i + '/' + total + '] ' + index);
            var derivedPrivateKey = bip32Ed25519.derivePrivate(xprv, index);
            var derivedPublicKey = bip32Ed25519.derivePublic(xpub, index);
            var toPublicKey = bip32Ed25519.toPublic(derivedPrivateKey);

            should.equal(derivedPublicKey.toString('hex'), toPublicKey.toString('hex'));

            const keyPair = eddsa.keyFromSecret(derivedPrivateKey.slice(0, 32));
            var publicKey = Buffer.from(keyPair.getPublic(true, true));
            should.equal(derivedPublicKey.slice(0, 32).toString('hex'), publicKey.toString('hex'));

            var message = Buffer.from('hello world');
            var sig = bip32Ed25519.sign(message, derivedPrivateKey);
            var verify = bip32Ed25519.verify(message, sig, derivedPublicKey);
            should.equal(verify, true, 'verify failed: index=' + index)
        }

        done();
    });

    it('derive', function(done) {
        var seed = Buffer.from('3660a6289d878f317fa7b180ce0b375178bd5ffe0ada03fca6905255fe25028166c802750d85f90bb0123b07608bbcfbc6b1be84519d68f37935e2a2a4b43cfe', 'hex');
        var path = 'm/53686/60791/4984';

        var xprv = bip32Ed25519.generateFromSeed(seed);
        console.log('xprv:', xprv.toString('hex'));

        var xpub = bip32Ed25519.toPublic(xprv);
        console.log('xpub:', xpub.toString('hex'));

        var indexes = path.split('/').slice(1);
        var xprv = bip32Ed25519.generateFromSeed(seed);
        var xpub = bip32Ed25519.toPublic(xprv);

        var derivedPrivateKey = xprv;
        var derivedPublicKey = xpub;

        for (var j = 0; j < indexes.length; j++) {
            derivedPrivateKey = bip32Ed25519.derivePrivate(derivedPrivateKey, parseInt(indexes[j]));
            derivedPublicKey = bip32Ed25519.derivePublic(derivedPublicKey, parseInt(indexes[j]));

            const keyPair = eddsa.keyFromSecret(derivedPrivateKey.slice(0, 32));
            var publicKey = Buffer.from(keyPair.getPublic(true, true));
            should.equal(derivedPublicKey.slice(0, 32).toString('hex'), publicKey.toString('hex'));

            var message = Buffer.from('hello world');
            var sig = bip32Ed25519.sign(message, derivedPrivateKey);
            var verify = bip32Ed25519.verify(message, sig, derivedPublicKey);
            should.equal(verify, true, 'verify failed')
        }

        done();
    });

    it('fromEntropy', function(done) {
        const mnemonic = 'expire found smooth ride piece swamp blast model slot fiction under gate escape animal reform'

        const path1 = "m/44'/1815'/0'"
        const expectedPublicKey1 = "ac9f7fabfa177eb5f5c44ae2a6bf84ede53bdbc256db64f22e9bcfdd8a82fb14015b1f5744f995b434f26e597e7aeae8c053a59fcb69aedf5c8c218846063eff"
        const path2 = "m/1852'/1815'/0'"
        const expectedPublicKey2 = "6b8d464521e3c433c33837a7aca2b70baaef19d48b8984f7a0eba66e32f3b62aedbdac20b6aa6bef253c15f9779487d6a5601ec35b915070c5370dceee11bd56"

        let key1 = bip32Ed25519.fromEntropy(Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex'))
        let arr1 = path1.split("/")
        for (let i = 1; i < arr1.length; i++) {
            key1 = bip32Ed25519.derivePrivate(key1, arr1[i].indexOf("'") > 0 ? (parseInt(arr1[i].slice(0, arr1[i].length - 1)) + 0x80000000) : parseInt(arr1[i]))
        }
        console.log(bip32Ed25519.toPublic(key1).toString('hex'))
        should.equal(bip32Ed25519.toPublic(key1).toString('hex'), expectedPublicKey1);

        let key2 = bip32Ed25519.fromEntropy(Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex'))
        let arr2 = path2.split("/")
        for (let i = 1; i < arr2.length; i++) {
            key2 = bip32Ed25519.derivePrivate(key2, arr2[i].indexOf("'") > 0 ? (parseInt(arr2[i].slice(0, arr2[i].length - 1)) + 0x80000000) : parseInt(arr2[i]))
        }
        console.log(bip32Ed25519.toPublic(key2).toString('hex'))
        should.equal(bip32Ed25519.toPublic(key2).toString('hex'), expectedPublicKey2);

        done();
    });
});
