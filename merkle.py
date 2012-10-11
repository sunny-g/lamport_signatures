#!/usr/bin/env python3
import lamport
import base64
from Crypto.Hash import SHA512
# lamport.py provides:
# - Keypair(existing_keypair):
#   -> generate_keypair - called automatically if keypair created empty
#   -> import_keypair - called if existing_keypair is provided; imports public or private keys.
#   -> verify_keypair - called after key import to check key validity, regenerate pubkey if needed.
#   -> tree_node_hash - Generates a pubkey hash for use in Merkle Trees.
#   -> export_public_key - Json export of public key as array of arrays.
#   -> export_private_key - Json export of private key as array of arrays.
#   -> export_keypair - Json export of dictionary with keys "public_key" and "private_key"#
# - Signer(Keypair):
#   -> generate_signature(string) - Generates b64-encoded signature.
#   -> hash_message(string/bytes) - Generates message hash
#   -> bit_hash(bytes) - Converts a binary hash into a list of bools representing the encoded bits.
# - Verifier:
#   -> verify_signature(message, utf8sig) - Verifies a message against a sig as produced by Signer.
#   -> verify_bin_signature(message, binsig) - Verifies binary message against binary sig.
#   -> hash_message(string/bytes) - As with Signer
#   -> bit_hash(bytes) - As with Signer

class MerkleTree:
    def __init__(self, keynum=128, ExistingTree=None):
        self.private_keyring = []
        self.public_keyring = []
        self.public_hashes = []
        self.hash_tree = [[]]
        self.used_keys = []
        self.signatures = []
        if not Tree:
            self.generate_keypairs(keynum)
            self.generate_tree()
        else:
            self.import_tree(Tree)
            self.verify_tree()

    def generate_keypairs(self, keynum):
        '''Generates keypairs and populates leaf nodes with pubkey hashes.'''
        while keynum > 0:
            keynum -= 1
            newkey = lamport.Keypair()
            self.public_keyring.append(newkey.export_public_key())
            self.private_keyring.append(newkey.export_private_key())
            self.hash_tree[0].append(newkey.tree_node_hash())            

    def generate_tree(self):
        'Uses initial leaf values to populate hash-tree.'
        # Below: While the length of the last item in the hash tree is greater than 1 (i.e. not root)
        while len(self.hash_tree[len(self.hash_tree)-1]) > 1:
            # Immediately create new empty list for new values.
            self.hash_tree.append([])
            # Tree depth so far, minus one so it can be used as a list index (starts at 0)
            tree_depth = len(self.hash_tree)-1
            # For each of the hashes in the layer below the new empty one:
            for node_hash in self.hash_tree[tree_depth-1][::2]:
                # Identify hash-pair at previous level to combine/hash:
                previous_node_index = self.hash_tree[tree_depth-1].index(node_hash)
                brother_node_index = previous_node_index + 1
                previous_node = self.hash_tree[tree_depth-1][previous_node_index]
                brother_node = self.hash_tree[tree_depth-1][brother_node_index]
                # Generate new hash above these two hashes:
                new_node_hash = SHA512.new(previous_node+brother_node).digest()
                # Embed new hash "above" constitutent hashes in new layer:
                self.hash_tree[tree_depth].append(new_node_hash)

    def export_tree(self):
        mytree = {'public_keys':self.public_keyring,
                  'private_keys':self.private_keyring,
                  'merkle_tree':self._exportable_tree(),
                  'signatures':self.signatures,
                  'used_keys':self.used_keys}

    def import_tree(self, tree):
        pass

    def _exportable_tree(self):
        exportable_tree = []
        for layer in self.hash_tree:
            exportable_tree.append([])
            for node_hash in layer:
                b64_str_hash = str(base64.b64encode(node_hash), 'utf-8')
                exportable_tree[len(exportable_tree)-1].append(b64_str_hash)
        return exportable_tree

    def verify_tree(self):
        pass

    def tree_public_key(self):
        return str(base64.b64encode(self.root_hash()),'utf-8')

    def root_hash(self):
        return self.hash_tree[len(self.hash_tree)-1]

    def sign_message(self, message, mark_used=True):
        'Finds unused key, uses to sign, marks used.'
        KeyToUse = self.select_unused_key()
        signature = KeyToUse.generate_signature(message)
        if mark_used: self.used_keys.append(KeyToUse.tree_node_hash())
        return signature

    def select_unused_key(self, mark_used=False):
        'Parses leaf nodes for hashes not in self.used_keys, returns first unused keypair.'
        counter = 0
        while self._is_used(self.hash_tree[0][counter]):
            counter += 1
        private_key = self.private_keyring[counter]
        public_key = self.public_keyring[counter]
        if mark_used: self.used_keys.append(KeyToUse.tree_node_hash())
        return lamport.Keypair({'public_key':public_key, 'private_key':private_key})

    def _is_used(self, leaf_hash):
        if leaf_hash in self.used_keys:
            return True
        else:
            return False
