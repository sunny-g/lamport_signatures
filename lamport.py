#!/usr/bin/env python3
'''An implementation of the Lamport Signature scheme.
Warning: written by an amateur. Use at your own risk!'''

global_debug = False
def debug_ln(debugstr):
    if global_debug:
        print(debugstr)

import sys
import os
import bitstring
import base64
import json
from hashlib import sha512

# Import a cryptographically secure random number generator.
# TODO: Put this in its own script.
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
    def __init__(self, private_seed=None, key_data=None, all_RNG=False, debug=False):
        '''Can be given a keypair to import and use, or generates one automatically.
        Default is to create a private keypair using hash-chaining (fast)
        If all_RNG is set to True (or any other value that evals True),
        private keys are instead built using raw RNG output.
        This is much slower and is more likely to cause blockage of RNGs that
        cannot produce enough random output to satisfy the lamport object's needs.'''
        self.debug = debug
        if private_seed:
            private_seed = self.import_seed(private_seed)
            self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_keypair(private_seed)
        elif key_data:
            self.private_key, self.public_key = self.import_keypair(key_data)
            self.rng_secret = None
        else:
            if all_RNG:
                self.private_key, self.public_key = self.generate_raw_random_keypair()
                self.rng_secret = None
            else:
                # Default behaviour without arguments.
                self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_keypair(preserve_secrets=True)
        # Runs some sanity checks on key data.
        self.verify_keypair()

    # N00b note: @staticmethod removes need to have "self" as method
    # first argument, and offers very marginal performance increase.
    # This means, of course, that these methods cannot alter the state
    # of the object, as they have not been passed the object/instance.
    @staticmethod
    def _bin_b64str(binary_stuff):
        'Utility method for converting bytes into b64-encoded strings.'
        return str(base64.b64encode(binary_stuff), 'utf-8')

    @staticmethod
    def _b64str_bin(b64_encoded_stuff):
        'Restores bytes data from b64-encoded strings.'
        return base64.b64decode(bytes(b64_encoded_stuff, 'utf-8'))

    @staticmethod
    def string_digest(string, digestsize):
        "Yield successive digestsize-sized chunks from string."
        for i in range(0, len(string), digestsize):
            yield string[i:i+digestsize]

    @staticmethod
    def _bin_list_peek(list_of_bytes, n=10):
        'Returns the first n bytes of every list item as b64 strings in a list.'
        # Useful for debugging, where looking at whole values or raw binary
        # would be cumbersome and difficult to compare against.
        return [str(base64.b64encode(x[:n]),'utf-8') for x in list_of_bytes]

    def generate_raw_random_keypair(self):
        '''Generates one sha512 lamport keypair for this object.
        Returns private key (list of lists), public key (list of lists).
        It is recommended to use generate_hash_chain_keypair instead, as
        it is far faster and less likely to block the RNG.'''
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

    def generate_hash_chain_keypair(self, secret_seeds=None, preserve_secrets=False):
        '''Saves on CSPRNG output by using a secret seed to generate
        secret hash chains, and then generating the public hash of each
        secret hash as pubkey.
        In order to prevent derivation of the entire private key upon
        publication of some secret hashes, each subsequent hash in the
        private hash-chains are seeded with the secret RNG output as well
        as the prior hash.
        The secret RNG output is currently discarded after private key
        generation, but may be retained for re-derivation of the private
        key from the seed in future, to allow for far smaller private keys.
        This method is nearly ten times faster than using raw RNG output.
        '''
        if secret_seeds:
            # TODO Sanity check secret seeds.
            pass
        else:
            # Generate a pair of large seeds for use in generating
            # the private key hash-chain.
            secret_seeds = [RNG(1024), RNG(1024)]
        # Debug only, to verify that secrets are different and consistent:
        private_key = []
        prior_hashes = [sha512(i).digest() for i in secret_seeds]
        for i in range(0,512):
            # Make new hash functions
            new_hashes = [sha512(), sha512()]
            # Make room for the digests to be added to private_key
            append_hashes = []
            for i in range(0,2):
                # Add prior hash for this position to new hash object:
                new_hashes[i].update(prior_hashes[i])
                # "Salt" the new hash with the secret seed for this position:
                new_hashes[i].update(secret_seeds[i])
                # Digest hash..
                i_digest = new_hashes[i].digest()
                # Replace the (now used) prior hash with a new "prior hash"
                prior_hashes[i] = i_digest
                # Append the new digest to the append_hashes list: this
                # will contain two hashes after this for-loop.
                append_hashes.append(i_digest)
            # Add the two new secret-salted hash-chain hashes to key list
            private_key.append(append_hashes)
        # Derive pubkey from private key in the usual way..
        public_key = self.rebuild_pubkey(private_key)
        # Debug only:
        if self.debug:
            print("Seed value headers:",self._bin_list_peek(secret_seeds))
            print("First 5 private key '0' values:",self._bin_list_peek([x[0] for x in private_key[:5]], 8))
            print("First 5 private key '1' values:",self._bin_list_peek([x[1] for x in private_key[:5]], 8))
            print("First 5 public key '0' values:",self._bin_list_peek([x[0] for x in public_key[:5]], 8))
            print("First 5 public key '1' values:",self._bin_list_peek([x[1] for x in public_key[:5]], 8))
        if preserve_secrets:
            secret_seeds = self._bin_b64str(secret_seeds[0]+secret_seeds[1])
            return private_key, public_key, secret_seeds
        else:
            # This might encourage the garbage collector to more proactively
            # delete our secrets. Maybe.
            del(secret_seeds)
            return private_key, public_key, None

    def import_seed(self, seed_str):
        seed_bytes = self._b64str_bin(seed_str)
        seed_len = int(len(seed_bytes)/2)
        seeds = [seed_bytes[:seed_len],seed_bytes[seed_len:]]
        return seeds

    def rebuild_pubkey(self, privkey=None):
        'Takes a list of value-pairs (lists or tuples), returns hash-pairs.'
        if not privkey: privkey = self.private_key
        def hashpair(pair):
            return [sha512(pair[0]).digest(), sha512(pair[1]).digest()]
        new_pubkey = []
        for priv_pair in privkey:
            new_pubkey.append(hashpair(priv_pair))
        return new_pubkey

    def tree_node_hash(self, b64=False):
        '''Used to generate pubkey hash for Merkle-Tree generation.
        This method simply concatenates each pubkey hash-pair end-on-end
        to create a long string of X1Y1X2Y2X3Y3..., then returns the
        sha512 hash of this string.'''
        flattened_pubkey = b''.join([b''.join(unitpair) for unitpair in self.public_key])
        merkle_node_hash = sha512(flattened_pubkey).digest()
        if b64:
            merkle_node_hash = self._bin_b64str(merkle_node_hash)
        return merkle_node_hash

    # n00b note: the "@property" decorator means that the following
    # method can be called without brackets or arguments. In otherwords,
    # a key's hash can be obtained using my_key.pubkey_hash - as if it
    # were a static property.
    @property
    def pubkey_hash(self):
        'Returns the base-64 encoded pubkey hash.'
        return self.tree_node_hash(True)

    def export_key_seed(self):
        '''Returns a dictionary with RNG seeds and merkle-tree hash.
        This is intended for minimised merkle trees, where seeds can be
        indexed by node hash and used to re-derive the lamport keypair
        as-needed. This minimises the space needed to store the Merkle
        tree in full, and reduces encryption/decryption time for
        passphrase-protected Merkle trees.
        '''
        if not self.rng_secret:
            raise AttributeError("This keypair object does not have the"+\
                      " required 'rng_secret' attribute; perhaps it was"+\
                      " imported from a raw keypair rather than a secret seed?")
        return {"Private Seed":self.rng_secret, "Leaf Hash":self.tree_node_hash(b64=True)}

    def export_keypair(self):
        return self.export_key_seed()["Private Seed"]

    def export_public_key(self):
        return json.dumps({'pub':self._exportable_key(self.public_key)})

    def export_private_key(self):
        return json.dumps({'sec':self._exportable_key(self.private_key)})

    def _exportable_key(self, key=None):
        if key is None:
            key= self.public_key
        export_key = []
        for unit in key:
            unit0 = self._bin_b64str(unit[0])
            unit1 = self._bin_b64str(unit[1])
            export_key.append([unit0, unit1])
        return export_key

    def _blockify_pubkey(self):
        'Flattens pubkey into a concatenated string of 88-char b64-encoded units.'
        export_key = self._exportable_key()
        flat_key = []
        for unit in export_key:
            flat_key.append(''.join(unit))
        flat_key = ''.join(flat_key)
        return flat_key

    @property
    def pubkey(self):
        return self._blockify_pubkey()

    def _deblockify_pubkey(self, concat_pubkey):
        'Decodes a concatenated pubkey string into pubkey hash-pair list.'
        raw_hashlist = []
        # For 512-bit digests like sha512, the raw digest size in bytes
        # is 64 bytes. But in base-64 encoding, it's 88 characters.
        for chopped_hash in self.string_digest(foo, 88):
            raw_hashlist.append(self._b64str_bin(chopped_hash))
        # "zip" is a builtin that runs through two or more iterables
        # and returns tuples of all the outputs. So, it's a convenient
        # way to do pairing of adjecent list items.
        hashpairs = zip(raw_hashlist[::2], raw_hashlist[1::2])
        # ..but we want lists, not tuples. Just in case it leads to bugs.
        hashpairs = [list(x) for x in hashpairs]
        return hashpairs

    def import_keypair(self, keypair):
        def parse_key(key):
            key_bin = []
            for unit_pair in key:
                unit0 = self._b64str_bin(unit_pair[0])
                unit1 = self._b64str_bin(unit_pair[1])
                key_bin.append([unit0, unit1])
            return key_bin
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
                if num_pair[0] == num_pair[1]:
                    raise ValueError("Number pairs in key must not be identical!")
                if not (isinstance(num_pair[0], bytes) or isinstance(num_pair[1], bytes)):
                    raise TypeError("Hash or Number pairs must be 64-byte (512-bit) binary sequences.")
                if len(num_pair[0]) != 64 or len(num_pair[1]) != 64:
                    raise TypeError("Hash or Number pairs must be 64-byte (512-bit) binary sequences.")

        if not self.private_key:
            if not self.public_key:
                raise TypeError("No keypair found!")
            else:
                check_key(self.public_key)
                if self.debug:
                    print("Only pubkey found. Can verify; cannot sign.")
                return True
        else:
            check_key(self.private_key)
            if self.public_key:
                check_key(self.public_key)
            else:
                self.public_key = self.rebuild_pubkey()
            if self.debug:
                print("Private key found. Can sign and verify self-signed messages.")
            return True

class KeyWrapper:
    def __init__(self, keypair):
        self.keypair = keypair
        
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
        # There is a reason we're converting booleans (low-memory usage)
        # to ints (probably higher memory usage): the values for each
        # bit will be used as list indices for selecting which pubkey hash
        # or private key number to use when signing and verifying.
        # TODO: Run some comparisons and performance checks to see if
        # it's faster to use booleans and if/else clauses instead.
        return [int(x) for x in list(hash_bits.bin)]

class Signer(KeyWrapper):
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

class Verifier(KeyWrapper):
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
        if self.keypair.debug:
            print("Bithash 1-30: ", ''.join([str(x) for x in bithash[:40]]))
            print("Counter", "Bit", "This Secret Num #", "Pubkey #", "Other Pubkey #", sep="\t")
        counter = 0
        for bit in bithash:
            public_hashes_for_bit = self.keypair.public_key[counter]
            this_number_hash = sha512(binsig[counter]).digest()
            # In python compound evaluations short-circuit, so if debug
            # is false, counter < 10 isn't even evaluated.
            if self.keypair.debug and counter < 10:
                # Get tib, the opposite of bit:
                if bit: tib = 0
                else: tib = 1
                print(counter, bit, base64.b64encode(this_number_hash[:10]), base64.b64encode(public_hashes_for_bit[bit][:10]), base64.b64encode(public_hashes_for_bit[tib][:10]), sep="\t")
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
        # Keypairs already have a string-digesting staticmethod, so use that.
        binary_sig = base64.b64decode(bytes(utf8sig, 'utf-8'))
        bin_sig_list = [x for x in self.keypair.string_digest(binary_sig, 64)]
        return bin_sig_list

def sign_action(*args, **kwargs):
    pass

def verify_action(*args, **kwargs):
    pass

def generate_action(*args, **kwargs):
    "Expects 'publickey' and 'privatekey' args (filenames to save to)."
    new_key = Keypair()
    private_key = new_key.export_key_seed()
    public_key = new_key.export_public_key()
    with open(kwargs['privatekey'], mode='w') as OutFile:
        OutFile.write(private_key['Private Seed'])
    with open(kwargs['publickey'], mode='w') as OutFile:
        OutFile.write(public_key)

def test_action(*args,**kwargs):
    mymsg = "This is a secret message!"
    print("Generating Lamport Keypair..")
    mykp = Keypair()
    print("Generating Pubkey..")
    mypubkey = mykp.export_public_key()

    print("Testing keypair export..")
    exp_mykp = mykp.export_keypair()
    # This is the secret seed pair, exported as a single contiguous
    # b64-encoded, utf-8 string.
    print("Testing keypair import..")
    del(mykp)
    mykp = Keypair(exp_mykp)

    print("Testing secret key export..")
    myseckey = mykp.export_private_key()
    # This is the actual secret key, as derived from the secret seeds,
    # as a utf-8 string JSON-exported list of b64-encoded value pair lists.
    print("Testing secret key import..")
    del(mykp)
    mykp = Keypair(key_data=myseckey)

    print("Initialising Signer and Verifier..")
    mysigner = Signer(mykp)
    myverifier = Verifier(Keypair(key_data=mypubkey))

    print("Generating Authentic Signature for message:\r\n\t{0}".format(mymsg))
    mysig = mysigner.generate_signature(mymsg)
    print("Attempting to Verify Signature...Result:", myverifier.verify_signature(mymsg, mysig))

    falsemsg = mymsg+" I grant Cathal unlimited right of attourney!"
    print("Attempting to Verify a Falsified Signature for message:\r\n\t{0}".format(falsemsg))
    print("Verification Result:",myverifier.verify_signature(falsemsg, mysig))

    print("Finished!")

if __name__ == "__main__":
    import argparse
    ScriptDescription = ('A key generator and signature generator/verifyer'
                         ' for the Lamport signature scheme, utilising'
                         ' minimised private keys and the SHA-512 hash'
                         ' algorithm for maximum integrity versus quantum'
                         ' computation.')
    ScriptEpilogue = ('A project by Cathal Garvey, licensed under the'
                      ' GNU General Public License v3: https://www.gnu.org/licenses/gpl.html'
                      ' - Code and other projects hosted on Gitorious: https://gitorious.org/~cathalgarvey')
    MainParser = argparse.ArgumentParser(description=ScriptDescription, epilog=ScriptEpilogue)
    Parsers = MainParser.add_subparsers(help="Subcommand or Mode:")
    # Will built parsers below. For each parser, will embed a function property
    # called "action_function" which will handle all the arguments passed
    # to the script when calling this parser.

    # First up: Generate a lamport keypair for later use with "sign" or "verify".
    KeygenParser = Parsers.add_parser("generate", help="Generate a Lamport keypair.")
    KeygenParser.set_defaults(action_function = generate_action)
    KeygenParser.add_argument("privatekey", help="Filename to save the private key as.")
    KeygenParser.add_argument("publickey", help="Filename to save the public key as.")

    # Use a specified Lamport key to sign a file or message.
    SignParser = Parsers.add_parser('sign', help="Sign a message or file.")
    SignParser.set_defaults(action_function = sign_action)

    # Use a Lamport public key to verify a signature against a file or message.
    VerifyParser = Parsers.add_parser("verify", help="Verify a signature against message or file.")
    VerifyParser.set_defaults(action_function = verify_action)
    
    # Run tests on the script; mainly used for development.
    TestParser = Parsers.add_parser("test", help="Run some tests to verify the script. Mainly used for development.")
    TestParser.set_defaults(action_function = test_action)

    Args = vars(MainParser.parse_args())
    # Pass the argument namespace to its "action_function" function, as specified above.
    Args['action_function'](**Args)
