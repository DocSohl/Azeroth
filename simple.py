from __future__ import print_function

from RSA import gen_keys
from RSA import crypt

import json
import random
import os
import getpass
import argparse
import hashlib
from builtins import input


class Session(object):
    def __init__(self, load=True):
        self.public = None
        self.private = None
        self.contacts = None
        self.config_location = os.path.expanduser("~/.azeroth")
        if load is True:
            if os.path.exists(self.config_location):
                self.load_config()
            else:
                self.create_config()

    def load_config(self):
        with open(self.config_location,"r") as f:
            config = json.load(f)

        # passphrase = getpass.getpass("Please enter your passphrase: ")
        # if len(passphrase) != 10:
        #     raise Exception("Passphrase is wrong length")
        passphrase = ""

        self.public = config["public"]
        self.private = passphrase+config["private"]
        self.contacts = config["contacts"]

    def create_config(self):
        self.public, self.private = gen_keys.gen_keys()
        # passphrase = self.private[:10]
        # priv_save = self.private[10:]
        # print("Your passphrase is:\n{0}\n\nYour public key is:\n{1}".format(str(passphrase), str(self.public)))
        priv_save = self.private
        print("Your public key is:\n{0}".format(str(self.public)))

        config = {"public":str(self.public), "private":str(priv_save), "contacts":{}}
        with open(self.config_location, "w") as f:
            json.dump(config, f)

    def save_config(self):
        with open(self.config_location,"r") as f:
            config = json.load(f)

        config["contacts"] = self.contacts

        with open(self.config_location, "w") as f:
            json.dump(config, f)

    def add_contact(self, contact_name, contact_public):
        self.contacts[contact_name] = contact_public
        self.save_config()

    def encrypt(self, contact_name, message):
        # digest = hashlib.sha1(message.encode()).hexdigest()
        # signature = crypt.encrypt(self.private, digest)
        # payload = {"message" : message, "signature" : signature}
        payload = {"message": message}
        contact_key = self.contacts[contact_name]
        return crypt.encrypt(contact_key, json.dumps(payload))

    def decrypt(self, contact_name, encoded):
        decoded = crypt.decrypt(self.public, self.private, encoded)
        try:
            payload = json.loads(decoded)
        except ValueError:
            raise Exception("Message contents are invalid")

        if "message" not in payload:# or "signature" not in payload:
            raise Exception("Message contents are invalid")

        if contact_name is None:
            print("WARNING: No signature validation")
        else:
            digest = hashlib.sha1(payload["message"].encode()).hexdigest()
            contact_key = self.contact[contact_name]
            sig_digest = crypt.decrypt(contact_key, payload["signature"])

            if digest != sig_digest:
                print("WARNING: Message signature could not be validated!")

        return payload["message"]

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Send and receive RSA encrypted messages")
    parser.add_argument("--new", action="store_true", help="Generate a new identity")
    parser.add_argument("--add", action="store_true", help="Add a new contact")
    parser.add_argument("--send", action="store_true", help="Send a message to an existing contact")
    parser.add_argument("--receive", action="store_true", help="Receive a message from an existing contact")
    parser.add_argument("--receive-no-validate", action="store_true", help="Receive a message without signature validation")
    parser.add_argument("--test", action="store_true", help="Encrypt and decrypt a message")
    args = parser.parse_args()
    if args.new or args.add or args.send or args.receive or args.receive_no_validate or args.test:
        s = Session(load=(not args.new))
    if args.new:
        print("Generating new configuration...")
        s.create_config()
        print("")
    if args.add:
        contact_name = input("Enter contact name: ")
        contact_public = input("Enter contact public key: ")
        s.add_contact(contact_name, contact_public)
        print("Contact added")
        print("")
    if args.send:
        contact_name = input("Enter contact name: ")
        message = input("Enter message to send: ")
        encoded = s.encrypt(contact_name, message)
        print("Encoded message:\n{0}".format(str(encoded)))
        print("")
    if args.receive:
        contact_name = input("Enter contact name: ")
        encoded = input("Enter received message: ")
        message = s.decrypt(contact_name, encoded)
        print("Received message:\n{0}".format(str(message)))
        print("")
    if args.receive_no_validate:
        encoded = input("Enter received message: ")
        message = s.decrypt(None, encoded)
        print("Received message:\n{0}".format(str(message)))
        print("")
    if args.test:
        print("Encrypting")
        encoded = s.encrypt("me", "test")
        print("Decrypting")
        message = s.decrypt(None, encoded)
        print("Received message:\n{0}".format(str(message)))
