#!/usr/bin/env python3
'''An implementation of the Lamport Signature scheme.
Warning: written by an amateur. Use at your own risk!'''

from Crypto import Random
from Crypto.Hash import SHA512
import bitarray
import base64
import json

class Keypair:
    def __init__(self, keypair=None):
        if keypair:
            self.private_key, self.public_key = self.import_keypair(keypair)
            self.verify_keypair()
        else:
            self.private_key, self.public_key = self.generate_keypair()

    def generate_keypair(self, leaf_hash=True):
        '''Generates one SHA512 lamport keypair for this object.
        Returns private key (list of lists), public key (list of lists).'''
        private_key = []
        public_key = []
        RNG = Random.new()
        for i in range(0,512):
            # Creates a pair of 512-bit numbers
            private_unit = [RNG.read(64),RNG.read(64)]
            # Creates a pair of 512-bit digests from the above
            public_unit = [SHA512.new(j).digest() for j in private_unit]
            # Adds the numbers and hashes to the end of the growing keys
            private_key.append(private_unit)
            public_key.append(public_unit)
        return private_key, public_key

    def rebuild_pubkey(self, privkey=None):
        if not privkey: privkey = self.private_key
        def hashpair(pair):
            return [SHA512.new(pair[0]).digest(), SHA512.new(pair[1]).digest()]
        new_pubkey
        for priv_pair in privkey:
            new_pubkey.append(hashpair(priv_pair))
        return new_pubkey

    def tree_node_hash(self):
         flattened_pubkey = b''.join([b''.join(unitpair) for unitpair in self.public_key])
         merkel_node_hash = SHA512.new(flattened_pubkey).digest()
         return merkel_node_hash

    def export_keypair(self):
        exportable_publickey = self._exportable_key(self.public_key)
        exportable_privatekey = self._exportable_key(self.private_key)
        b64keypair = {'public_key':exportable_publickey,
                      'private_key':exportable_privatekey}
        return json.dumps(b64keypair)

    def export_public_key(self):
        return json.dumps(self._exportable_key(self.public_key))

    def export_private_key(self):
        return json.dumps(self._exportable_key(self.private_key))

    def _exportable_key(self, key=None):
        if key is None: key= self.public_key
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
        keypair = json.loads(keypair)
        available_keys = keypair.keys()
        if 'private_key' in available_keys and 'public_key' in available_keys:
            return parse_key(keypair['private_key']), parse_key(keypair['public_key'])
        elif 'private_key' in available_keys:
            privkey = parse_key(keypair['private_key'])
            return privkey, self.rebuild_pubkey(privkey)
        elif 'public_key' in available_keys:
            return None, parse_key(keypair['public_key'])

    def verify_private_key(self):
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
                print("Only pubkey found. Can verify; cannot sign.")
                return True
        else:
            check_key(self.private_key)
            if self.public_key:
                check_key(self.public_key)
            else:
                self.public_key = self.rebuild_pubkey()

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
            Revealed_Numbers.append(private_numbers_for_bit[int(bit)])
            counter += 1
        return Revealed_Numbers

    def hash_message(self, message):
        if not isinstance(message, bytes):
            message = bytes(message,'utf-8')
        return SHA512.new(message).digest()

    def bit_hash(self, message_hash):
        'Returns a list of bools representing the bits of message_hash'
        if not isinstance(message_hash, bytes):
            raise TypeError(("message_hash must be a binary hash, "
                             "as returned by SHA512.digest()"))
        hash_binary = bitarray.bitarray(endian='big')
        hash_binary.frombytes(message_hash)
        if hash_binary.length() != 512:
            raise ValueError("Message hash must be 512 bits in length.")
        return hash_binary.tolist()

class Verifier:
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.public_key:
            raise ValueError(("Specified key has no public part, "
                   "and generation from private part (if available) "
                   "failed. Cannot be used to verify."))

    def verify_utf8_signature(self, message, utf8sig):
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
            this_number_hash = SHA512.new(binsig[counter]).digest()
            # Below: int(bit) returns 1 or 0 according to bool value.
            if this_number_hash != public_hashes_for_bit[int(bit)]:
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
        return SHA512.new(message).digest()

    def bit_hash(self, message_hash):
        'Returns a list of bools representing the bits of message_hash'
        if not isinstance(message_hash, bytes):
            raise TypeError(("message_hash must be a binary hash, "
                             "as returned by SHA512.digest()"))
        hash_binary = bitarray.bitarray(endian='big')
        hash_binary.frombytes(message_hash)
        if hash_binary.length() != 512:
            raise ValueError("Message hash must be 512 bits in length.")
        return hash_binary.tolist()
