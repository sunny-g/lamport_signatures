#!/usr/bin/env python3
import lamport
import base64
import json
from hashlib import sha512

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

class KeyManagementError(Exception):
    pass

class MerkleTree:
    def __init__(self, keynum=128, ExistingTree=None, hash_chain_keys=True):
        self.private_keyring = []
        self.public_keyring = []
        self.public_hashes = []
        self.hash_tree = [[]]
        self.used_keys = []
        self.signatures = []
        if hash_chain_keys:
            self.key_type = "hash chain"
        else:
            self.key_type = "raw RNG"
        if not ExistingTree:
            self.generate_keypairs(keynum)
            self.generate_tree()
        else:
            self.import_tree(ExistingTree)
            self.verify_tree()

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

    def generate_keypairs(self, keynum):
        if self.key_type == "hash chain":
            self._generate_hashchain_keypairs(keynum)
        elif self.key_type == "raw RNG":
            self._generate_RNG_keypairs(keynum)
        else:
            pass

    def _generate_RNG_keypairs(self, keynum):
        '''Generates keypairs and populates leaf nodes with pubkey hashes.'''
        while keynum > 0:
            keynum -= 1
            newkey = lamport.Keypair()
            self.public_keyring.append(newkey.export_public_key())
            self.private_keyring.append(newkey.export_private_key())
            self.hash_tree[0].append(newkey.tree_node_hash())

    def _generate_hashchain_keypairs(self, keynum):
        while keynum > 0:
            keynum -= 1
            newkey = lamport.Keypair()
            key_seed = newkey.export_key_seed()
            # key_seed contains "Private Seed", "Leaf Hash": both b64 str
            self.private_keyring.append(key_seed['Private Seed'])
            self.public_keyring.append(key_seed['Leaf Hash'])
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
                new_node_hash = sha512(previous_node+brother_node).digest()
                # Embed new hash "above" constitutent hashes in new layer:
                self.hash_tree[tree_depth].append(new_node_hash)

    def export_tree(self, passphrase=None):
        # Desired features include a symmetric encryption function.
        mytree = {'public_keys':self.public_keyring,
                  'private_keys':self.private_keyring,
                  'merkle_tree':self._exportable_tree(),
                  'signatures':self.signatures,
                  'used_keys':self.used_keys}
        return json.dumps(mytree)

    def import_tree(self, tree):
        # Desired features include detecting an encrypted tree
        #  and prompting for a decryption passphrase.
        print("Tree import not yet implemented!")

    def _exportable_tree(self):
        exportable_tree = []
        for layer in self.hash_tree:
            exportable_tree.append([])
            for node_hash in layer:
                b64_str_hash = self._bin_b64str(node_hash)
                exportable_tree[len(exportable_tree)-1].append(b64_str_hash)
        return exportable_tree

    def verify_tree(self):
        '''Should verify that all hashes in the tree match up, that
        numbers of nodes at each level are correct.'''
        print("Tree verification not yet implemented!")

    def tree_public_key(self):
        'Returns the root node as a base-64 encoded string.'
        return self._bin_b64str(self.root_hash())

    def root_hash(self):
        'Returns the root node as binary.'
        return self.hash_tree[len(self.hash_tree)-1]

    def _sign_message(self, message, include_nodes=True,
                           include_pubkey=True, mark_used=True,
                           force_sign = False):
        '''Burns an unused key, returns a dict containing signature dict.
        Signature dict contains "lamport_pubkey" (str), "lamport_signature" (str),
        and "node_path" (list of two-member (string-hash/None) list).
        This dict can be used by other methods to construct a wire/pub-friendly
        signature, or directly passed to other systems for verification.'''
        KeyToUse = self.select_unused_key(mark_used=True, force=force_sign)
        signer = lamport.Signer(KeyToUse)
        signature = {}
        signature["lamport_signature"] = signer.generate_signature(message)
        signature["lamport_pubkey"] = KeyToUse._exportable_key()
        signature["paired_nodes"] = self.get_node_path(KeyToUse.tree_node_hash())
        return signature

    def get_node_path(self, leaf_hash, cue_pairs=True, verify_nodes=True):
        '''Returns a list of node-hashes to pair with to derive root node.
        First, this method uses list indexing to locate the leaf_hash.
        If this number is 0 or even, it pairs with the next node.
        If this number is odd, it pairs with the previous node.
        To determine the pair-node of this pairing, the leaf index is
        divided by two and floored. This new index is used as above to
        determine the hashing partner for the next node, and so on.
        Each node is returned within a two-item list, the other item
        being empty to designate where the "current node" belongs when
        hashing toward the root node/hash. Set "cue_pairs" to False to
        disable this behaviour and return a straight list of nodes.
        Before returning the list, if verify_nodes is True, this method
        will verify that the list will indeed derive the root hash,
        raising KeyManagementError if not.'''
        # Yes, saving string/None pairs as tuples would make this more
        # efficient, but this is intended for JSON-export among other
        # export formats, and Tuples are not supported by straight JSON.
        if leaf_hash not in self.hash_tree[0]:
            raise KeyManagementError("Specified leaf_hash not in leaves"+\
                                  " of Merkle Tree. Hash requested was: "+\
                                  str(leaf_hash,'utf-8'))
        node_list = []
        node_number = self.hash_tree[0].index(leaf_hash)
        level_num = 0
        for level in self.hash_tree:
            level_num += 1
            if level_num == len(self.hash_tree):
                break
            if node_number % 2:
                # i.e., if odd: so, use prior node as partner.
                if cue_pairs:
                    node_list.append([self._bin_b64str(level[node_number-1]), None])
                else:
                    node_list.append(self._bin_b64str(level[node_number-1]))
            else:
                # i.e., if even, so use next node as partner.
                if cue_pairs:
                    node_list.append([None, self._bin_b64str(level[node_number+1])])
                else:
                    node_list.append(self._bin_b64str(level[node_number+1]))
            # Get the node number for the next level of the hash-tree.
            # Oddly, using int() is faster than using math.floor() for
            # getting the pre-decimal value of a positive float.
            node_number = int(node_number/2)
        if verify_nodes:
            pass
            #if not self.derive_root()
        return node_list

    def select_unused_key(self, mark_used=True, force=False):
        'Parses leaf nodes for hashes not in self.used_keys, returns first unused keypair.'
        # First, check that we're not on our last key; if so, unless
        # the "force" flag is set True, raise a KeyManagementError
        # suggesting that the last key be used to sign a new tree.
        if len(self.used_keys) == len(self.hash_tree[0]) - 1:
            if not force:
                raise KeyManagementError("Only one key remains; you should use this key "+\
                        "to sign a new Merkle tree so as not to waste any trust signatures"+\
                        "accrued during the lifetime of this tree.")
        # Find an unused key by cycling through tree "leaves" and comparing
        # to a list of used leaves.
        counter = 0
        while self._is_used(self.hash_tree[0][counter]):
            counter += 1
        private_key = self.private_keyring[counter]
        if private_key is None:
            raise KeyManagementError(
                  "Selected 'unused' key appears to have been used.")
        # Import key as a lamport Keypair.
        try:
            if self.key_type == "hash chain":
                keypair = lamport.Keypair(private_seed = private_key)
            else:
                keypair = lamport.Keypair(keypair = private_key)
        except IndexError as e:
            print("While attempting to create a keypair with the following:",
                  keypair_to_import,"..an error occurred:", e, sep="\r\n")
        # Check key to make sure it matches its leaf hash:
        try: assert(keypair.tree_node_hash() == self.hash_tree[0][counter])
        except AssertionError:
            raise KeyManagementError("Tree leaf node does not match keypair hash generated on-the-fly.")
        if mark_used:
            # Don't just mark it used, delete the key so it can't be used
            # again by accident!
            self.mark_key_used(keypair.tree_node_hash())
            self.private_keyring[counter] = None
        return keypair

    def fetch_key(self, leaf_hash, key='public_key'):
        '''For fetching a keypair from the keyring by leaf node hash.
        By default, seeks/returns the pubkey, but if key is "private_key"
        then this returns that instead.'''
        raise NotImplementedError()

    def mark_key_used(self, leaf_hash, delete_private=True):
        'Marks a key, specified by leaf_hash, as used. Optionally deletes private key.'
        # Deleting old private keys is probably good security practice and saves space.
        # Before deleting private keys, ensure that system is robust at using pubkeys
        # and doesn't rely on regenerating from private keys.
        # Also ensure that private keys are overwritten, not popped, so list indices
        # remain relative between pubkeys and private keys!
        # At present, this just appends a hash to a list.
        if leaf_hash not in self.used_keys:
            self.used_keys.append(leaf_hash)

    def _is_used(self, leaf_hash):
        if leaf_hash in self.used_keys:
            return True
        else:
            return False

def runtests():
    mytree = MerkleTree(4)
    mymsg = "This is a verifiable message."
    print("Attempting to sign the following:",mymsg,sep="\r\n\t")
    mysig = mytree._sign_message(mymsg)
    with open("testsig1.mlsig",mode='w') as SigOut:
        SigOut.write(json.dumps(mysig, indent=2))
    print("Signature successful, saved as testsig1.mlsig..")
    mymsg2 = "This is a second message.."
    mysig2 = mytree._sign_message(mymsg2)
    print("Attempting to sign the following:",mymsg2,sep="\r\n\t")
    mymsg3 = "..And a third.."
    mysig3 = mytree._sign_message(mymsg3)
    print("Attempting to sign the following:",mymsg3,sep="\r\n\t")
    mymsg4 = "..and a fourth, this should use the last key."
    mysig4 = mytree._sign_message(mymsg4)
    print("Attempting to sign the following:",mymsg4,sep="\r\n\t")
    mymsg5 = "..and a fifth; this shouldn't sign."
    mysig5 = mytree._sign_message(mymsg5)
    print("Attempting to sign the following:",mymsg5,sep="\r\n\t")

if __name__ == "__main__":
    runtests()
