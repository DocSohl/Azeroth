from __future__ import print_function

from RSA import gen_keys
from RSA import crypt

import json
import random
import os
import base64
import getpass
import argparse
import hashlib

class Session(object):
	def __init__(self):
		self.public = None
		self.private = None
		self.contacts = None
		self.config_location = os.path.expanduser("~/.azeroth")
		if os.path.exists(self.config_location):
			self.load_config()
		else:
			self.create_config()

	def load_config(self):
		with open(self.config_location,"r") as f:
			config = json.load(f)

		passphrase = getpass.getpass("Please enter your passphrase: ")
		if len(passphrase) != 10:
			raise Exception("Passphrase is wrong length")

		self.public = config["public"]
		self.private = bas64.b64decode(passphrase+config["private"])
		self.contacts = config["contacts"]

	def create_config(self):
		self.public, self.private = gen_keys.gen_keys()
		priv_encoded = base64.b64encode(self.private)
		passphrase = priv_encoded[:10]
		priv_save = priv_encoded[10:]

		print("Your passphrase is:\n%s\n\nYour public key is:\n", str(passphrase), str(self.public))

		config = {"public":self.public, "private":priv_save, "contacts":{}}
		with open(self.config_location, "w") as f:
			json.dump(config, f)

	def save_config(self):
		with open(self.config_location,"r") as f:
			config = json.load(f)

		config["contacts"] = self.contacts

		with open(self.config_location, "w") as f:
			json.dump(config, f)

	def add_contact(self, contact_name, contact_public):
		self.contacts["contact_name"] = contact_public
		self.save_config()

	def encrypt(self, contact_name, message):
		digest = hashlib.sha1(message.encode()).hexdigest()
		signature = crypt.encrypt(self.private, digest)
		payload = {"message" : message, "signature" : signature}
		return crypt.encrypt(contact[contact_name], json.dumps(payload))

	def decrypt(self, contact_name, encoded):
		decoded = crypt.decrypt(self.private, encoded)
		try:
			payload = json.loads(decoded)
		except ValueError:
			raise Exception("Message contents are invalid")

		if "message" not in payload or "signature" not in payload:
			raise Exception("Message contents are invalid")

		if contact_name is None:
			print("WARNING: No signature validation")
		else:
			digest = hashlib.sha1(payload["message"].encode()).hexdigest()
			sig_digest = crypt.decrypt(self.contacts[contact_name], payload["signature"])

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
	args = parser.parse_args()
	if args.new or args.add or args.send or args.receive or args.receive_no_validate:
		s = Session()
	if args.new:
		print("Generating new configuration...")
		s.create_config()
		print("")
	if args.add:
		contact_name = raw_input("Enter contact name: ")
		contact_public = raw_input("Enter contact public key: ")
		s.add_contact(contact_name, contact_public)
		print("Contact added")
		print("")
	if args.send:
		contact_name = raw_input("Enter contact name: ")
		message = raw_input("Enter message to send: ")
		encoded = s.encrypt(contact_name, message)
		print("Encoded message:\n%s", str(encoded))
		print("")
	if args.receive:
		contact_name = raw_input("Enter contact name: ")
		encoded = raw_input("Enter received message: ")
		message = s.decrypt(contact_name, encoded)
		print("Received message:\n%s", str(message))
		print("")
	if args.receive_no_validate:
		encoded = raw_input("Enter received message: ")
		message = s.decrypt(None, encoded)
		print("Received message:\n%s", str(message))
		print("")
