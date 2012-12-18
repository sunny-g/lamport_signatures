#!/usr/bin/env python3
'''An implementation of the Lamport Signature scheme.
Warning: written by an amateur. Use at your own risk!'''

global_debug = False
def debug_ln(debugstr):
    if global_debug:
        print(debugstr)

# Todo: remove the PyCrypto RNG requirement: new SSL RNG in Standard Library?
import sys
import os
import bitstring
import base64
import json
from hashlib import sha512

# Import a cryptographically secure random number generator.
try:
    # Introduced in Python 3.3 standard library: wraps OpenSSL/libssl
    from ssl import RAND_bytes as RNG
    debug_ln("Using ssl module for Random Number Generation.")
except ImportError:
    try:
        # Failing that, if PyCrypto is installed, can use that:
        from Crypto import Random
        _RNG = Random.new()
        RNG = _RNG.read
        debug_ln("Using PyCrypto module for Random Number Generation.")
    except ImportError:
        import fallback_RNG
        RNG = fallback_RNG.new()
        if os.name == "nt":
            winwarning = " On Windows, security workarounds borrowed from PyCrypto have been applied to try and ensure security on a terrible platform. Consider upgrading to Linux or BSD, or installing PyCrypto."
        else:
            winwarning = " On Unix/POSIX based platforms (which you seem to be using), os.urandom probably calls /dev/urandom, which should be cryptographically secure. For better assurance, consider upgrading to Python 3.3, or installing PyCrypto."
        print("Python Version is less than 3.3, and PyCrypto is not installed. Will use os.urandom for random bytes when generating keys."+winwarning)

class Keypair:
    def __init__(self, keypair=None, all_RNG=False):
        '''Can be given a keypair to import and use, or generates one automatically.
        Default is to create a private keypair using hash-chaining (fast)
        If all_RNG is set to True (or any other value that evals True),
        private keys are instead built using raw RNG output.
        This is much slower and is more likely to cause blockage of RNGs that
        cannot produce enough random output to satisfy the lamport object's needs.'''
        if keypair:
            self.private_key, self.public_key = self.import_keypair(keypair)
            self.verify_keypair()
        else:
            if all_RNG:
                self.private_key, self.public_key = self.generate_raw_random_keypair()
            else:
                self.private_key, self.public_key = self.generate_hash_chain_keypair()

    def generate_raw_random_keypair(self):
        '''Generates one sha512 lamport keypair for this object.
        Returns private key (list of lists), public key (list of lists).'''
        private_key = []
        public_key = []
        for i in range(0,512):
            # Creates a pair of 512-bit numbers
            private_unit = [RNG(64), RNG(64)]
            # Creates a pair of 512-bit digests from the above
            public_unit = [sha512(j).digest() for j in private_unit]
            # Adds the numbers and hashes to the end of the growing keys
            private_key.append(private_unit)
            public_key.append(public_unit)
        return private_key, public_key

    def generate_hash_chain_keypair(self):
        '''Saves on CSPRNG output by using a secret seed to generate
        secret hash chains, and then generating the public hash of each
        secret hash as pubkey.
        In order to prevent derivation of the entire private key upon
        publication of some secret hashes, each subsequent hash in the
        private hash-chains are seeded with the secret RNG output as well
        as the prior hash.
        The secret RNG output is discarded after private key generation.
        '''
        secret_seeds = [RNG(256), RNG(256)]
        private_key = []
        prior_hashes = [sha512(i).digest() for i in secret_seeds]
        for i in range(0,512):
            # Make new hash functions
            new_hashes = [sha512(), sha512()]
            # Make room for the digests to be added to private_key
            append_hashes = []
            for i in range(0,2):
                # Fill hash buffer with the previous hash digest for
                # this position
                new_hashes[i].update(prior_hashes[i])
                new_hashes[i].update(secret_seeds[i])
                i_digest = new_hashes[i].digest()
                prior_hashes[i] = i_digest
                append_hashes.append(i_digest)
            private_key.append(append_hashes)
        # Hasten destruction of now-defunct secret.
        del(secret_seeds)
        public_key = self.rebuild_pubkey(private_key)
        return private_key, public_key

    def rebuild_pubkey(self, privkey=None):
        if not privkey: privkey = self.private_key
        def hashpair(pair):
            return [sha512(pair[0]).digest(), sha512(pair[1]).digest()]
        new_pubkey = []
        for priv_pair in privkey:
            new_pubkey.append(hashpair(priv_pair))
        return new_pubkey

    def tree_node_hash(self):
        '''Used to generate pubkey hash for Merkle-Tree generation.
        This method simply concatenates each pubkey hash-pair end-on-end
        to create a long string of X1Y1X2Y2X3Y3..., then returns the
        sha512 hash of this string.'''
        flattened_pubkey = b''.join([b''.join(unitpair) for unitpair in self.public_key])
        merkel_node_hash = sha512(flattened_pubkey).digest()
        return merkel_node_hash

    def export_keypair(self):
        exportable_publickey = self._exportable_key(self.public_key)
        exportable_privatekey = self._exportable_key(self.private_key)
        b64keypair = {'pub':exportable_publickey,
                      'sec':exportable_privatekey}
        return json.dumps(b64keypair)

    def export_public_key(self):
        return json.dumps({'pub':self._exportable_key(self.public_key)})

    def export_private_key(self):
        return json.dumps({'sec':self._exportable_key(self.private_key)})

    def _exportable_key(self, key=None):
        if key is None:
            key= self.public_key
        export_key = []
        for unit in key:
            unit0 = str(base64.b64encode(unit[0]), 'utf-8')
            unit1 = str(base64.b64encode(unit[1]), 'utf-8')
            export_key.append([unit0, unit1])
        return export_key

    def import_keypair(self, keypair):
        def parse_key(key):
            key_in = []
            for unit_pair in key:
                unit0 = base64.b64decode(bytes(unit_pair[0],'utf-8'))
                unit1 = base64.b64decode(bytes(unit_pair[1],'utf-8'))
                key_in.append([unit0, unit1])
            return key_in
        if isinstance(keypair, str):
            keypair = json.loads(keypair)
        elif not isinstance(keypair, dict):
            raise TypeError("Only json-formatted strings or native dicts are supported for key import.")
        available_keys = keypair.keys()
        if 'sec' in available_keys and 'pub' in available_keys:
            return parse_key(keypair['sec']), parse_key(keypair['pub'])
        elif 'sec' in available_keys:
            privkey = parse_key(keypair['sec'])
            return privkey, self.rebuild_pubkey(privkey)
        elif 'pub' in available_keys:
            return None, parse_key(keypair['pub'])

    def verify_keypair(self):
        def check_key(key):
            if not isinstance(key, list):
                raise TypeError("Key must be a list.")
            if len(key) != 512:
                raise ValueError("Key must consist of 512 number-pairs.")
            for num_pair in key:
                if not isinstance(num_pair, list):
                    raise TypeError("Each hash or number pair in key must be a list.")
                if len(num_pair) != 2:
                    raise ValueError("Each hash or number pair list must be two items in size.")
                if not (isinstance(num_pair[0], bytes) or isinstance(num_pair[1], bytes)):
                    raise TypeError("Hash or Number pairs must be 64-byte (512-bit) binary sequences.")
                if len(num_pair[0]) != 64 or len(num_pair[1]) != 64:
                    raise TypeError("Hash or Number pairs must be 64-byte (512-bit) binary sequences.")

        if not self.private_key:
            if not self.public_key:
                raise TypeError("No keypair found!")
            else:
                check_key(self.public_key)
                debug_ln("Only pubkey found. Can verify; cannot sign.")
                return True
        else:
            check_key(self.private_key)
            if self.public_key:
                check_key(self.public_key)
            else:
                self.public_key = self.rebuild_pubkey()
            debug_ln("Private key found. Can sign and verify self-signed messages.")
            return True

class Signer:
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.private_key:
            raise ValueError("Specified key has no private part; cannot sign!")

    def generate_signature(self, message):
        '''Generate base-64 encoded string signature in utf-8.

        Signature is a concatenation of _generate_signature output.
        Verifiers can regenerate the binary signature by byte-decoding
        from utf-8, b64-decoding the binary, and breaking into 64byte chunks.
        '''
        binary_sig = self._generate_signature(message)
        concat_bin_sig = b''.join(binary_sig)
        b64_bin_sig = base64.b64encode(concat_bin_sig)
        utf8_sig = str(b64_bin_sig, 'utf-8')
        return utf8_sig

    def _generate_signature(self, message):
        'Generate binary signature as a list of 64-byte binary private numbers.'
        bithash = self.bit_hash(self.hash_message(message))
        Revealed_Numbers = []
        counter = 0
        for bit in bithash:
            private_numbers_for_bit = self.keypair.private_key[counter]
            # Below: if bit is true, int(bit) is 1, if False, 0.
            Revealed_Numbers.append(private_numbers_for_bit[bit])
            counter += 1
        return Revealed_Numbers

    def hash_message(self, message):
        if not isinstance(message, bytes):
            message = bytes(message,'utf-8')
        return sha512(message).digest()

    def bit_hash(self, message_hash):
        'Returns a list of bools representing the bits of message_hash'
        if not isinstance(message_hash, bytes):
            raise TypeError(("message_hash must be a binary hash, "
                             "as returned by sha512.digest()"))
        hash_bits = bitstring.BitString(message_hash)
        return [int(x) for x in list(hash_bits.bin)]

class Verifier:
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.public_key:
            raise ValueError(("Specified key has no public part, "
                   "and generation from private part (if available) "
                   "failed. Cannot be used to verify."))

    def verify_signature(self, message, utf8sig):
        '''Message and utf8sig should be strings. They will be byte-converted
        and passed to the verify_bin_signature method.'''
        return self.verify_bin_signature(bytes(message,'utf-8'), self._parse_utf8_sig(utf8sig))

    def verify_bin_signature(self, message, binsig):
        '''This is the method responsible for actual verification of sigs.

        Message must be binary. Binsig must be a list of 512 64-byte values.
        Messages are first hash-digested, and the hash is converted to a
        list of boolean values representing the bits of the hash. Then,
        for each boolean of the signature, a hash from the pubkey is chosen
        and compared to the hash of the number in the binary signature.
        If the hashes of all numbers in the signature match the corresponding
        hashes in the pubkey, the sig is valid, and this returns True.
        Otherwise, this method returns False.'''
        bithash = self.bit_hash(self.hash_message(message))
        counter = 0
        for bit in bithash:
            public_hashes_for_bit = self.keypair.public_key[counter]
            this_number_hash = sha512(binsig[counter]).digest()
            # Below: int(bit) returns 1 or 0 according to bool value.
            if this_number_hash != public_hashes_for_bit[bit]:
                # Hash mismatch, signature false.
                return False
            # Counter should run from 0 to 511
            counter += 1
        # No hash mismatch, signature valid.
        return True

    def _parse_utf8_sig(self, utf8sig):
        # NB: Should verify the general shape/format of the signature here.
        # Sig is a concatenation of 512 b64-encoded 64-byte numbers.
        # The length of such numbers is 88 when encoded.
        def chunks(l, n):
            "Generator: Yield successive n-sized chunks from l."
            for i in range(0, len(l), n):
                yield l[i:i+n]
        binary_sig = base64.b64decode(bytes(utf8sig, 'utf-8'))
        bin_sig_list = [x for x in chunks(binary_sig, 64)]
        return bin_sig_list

    def hash_message(self, message):
        if not isinstance(message, bytes):
            message = bytes(message,'utf-8')
        return sha512(message).digest()

    def bit_hash(self, message_hash):
        'Returns a list of bools representing the bits of message_hash'
        if not isinstance(message_hash, bytes):
            raise TypeError(("message_hash must be a binary hash, "
                             "as returned by sha512.digest()"))
        hash_bits = bitstring.BitString(message_hash)
        return [int(x) for x in list(hash_bits.bin)]

def test():
    mymsg = "This is a secret message!"
    print("Generating Lamport Keypair..")
    mykp = Keypair()
    print("Generating Pubkey..")
    mypubkey = mykp.export_public_key()
    print("Testing keypair export..")
    exp_mykp = mykp.export_keypair()
    print("Testing keypair import..")
    del(mykp)
    mykp = Keypair(exp_mykp)
    print("Testing secret key export..")
    myseckey = mykp.export_private_key()
    print("Testing secret key import..")
    del(mykp)
    mykp = Keypair(myseckey)
    print("Initialising Signer and Verifier..")
    mysigner = Signer(mykp)
    myverifier = Verifier(Keypair(mypubkey))
    print("Generating Authentic Signature for message:\r\n\t'{0}'".format(mymsg))
    mysig = mysigner.generate_signature(mymsg)
    print("Attempting to Verify Signature...Result:", myverifier.verify_signature(mymsg, mysig))
    falsemsg = mymsg+" I grant Cathal unlimited right of attourney!"
    print("Attempting to Verify a Falsified Signature for message:\r\n\t{0}".format(falsemsg))
    print("Verification Result:",myverifier.verify_signature(falsemsg, mysig))
    print("Finished!")

if __name__ == "__main__":
    test()
