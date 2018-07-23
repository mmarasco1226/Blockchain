import hashlib
import json
from time import time
from urllib.parse import urlparse
import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


import requests



class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.current_addresses = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):


        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            # if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
            if not self.valid_proof(last_block['proof'], block['proof'], self.hash(last_block)):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print(f"Querying chain on node: {node}")
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                # if length > max_length and self.valid_chain(chain):

                if length > max_length and self.valid_chain(chain) and length == len(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'addresses': self.current_addresses,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.current_addresses = []

        self.chain.append(block)

        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :return: The index of the Block that will hold this transaction
        """

        # Make sure sender has account and tokens to send

        if (sender != "0") and (sender not in self.balances()):

            return False, 'Sender not registered with blockchain'

        # Check sufficient funds
        if (sender != "0") and (self.balances()[sender] < amount):
            return False, 'Insufficient amount in account'

        #TODO: signature check, need to implement crypto
        # def verify_transaction_signature(self, sender_address, signature, transaction):
        #     """
        #     Check that the provided signature corresponds to transaction
        #     signed by the public key (sender_address)
        #     """
        #     public_key = RSA.importKey(binascii.unhexlify(sender_address))
        #     verifier = PKCS1_v1_5.new(public_key)
        #     h = SHA.new(str(transaction).encode('utf8'))
        #     return verifier.verify(h, binascii.unhexlify(signature))
        #-------------------------------------------------------------------------
        # if sender != "0":
        #     j = {'sender': sender, 'recipient': recipient, 'amount': amount}
        #     msg = f'sender:{j["sender"]},recipient:{j["recipient"]},amount:{j["amount"]}'
        #     pub_key = Key.fromstring(self.addresses()[sender])
        #     if not pub_key.verify_signature(signature, msg.encode()):
        #         print("invalid signature")
        #         return (False, "Signature invalid")

        def sign_transaction(self):
            """
            Sign transaction with private key
            """
            private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
            signer = PKCS1_v1_5.new(private_key)
            h = SHA.new(str(self.to_dict()).encode('utf8'))
            return binascii.hexlify(signer.sign(h)).decode('ascii')


        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    def balances(self):
        response = {}
        for c in self.chain:
            for t in c['transactions']:
                if t['sender'] not in response:
                    response[t['sender']] = 0
                if t['recipient'] not in response:
                    response[t['recipient']] = 0
                response[t['sender']] -= t['amount']
                response[t['recipient']] += t['amount']
        return response


    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
