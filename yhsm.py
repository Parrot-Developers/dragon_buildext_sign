#!/usr/bin/env python3

import argparse
import binascii
import getpass
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

from yubihsm import YubiHsm
from yubihsm.objects import AsymmetricKey
from yubihsm.defs import ALGORITHM, COMMAND

DEFAULT_SERVER = "https://noserver.parrot.biz"

def _get_server_url():
    return os.environ.get("YHSM_SERVER", DEFAULT_SERVER)


def _get_session_id():
    return os.environ.get("YHSM_SESSION_ID", None)


def _get_credential_file():
    return os.environ.get("YHSM_CREDENTIAL_FILE", None)


def _get_password():
    credential_file = _get_credential_file()
    if credential_file:
        with open(credential_file, "r") as fin:
            return fin.read()
    return getpass.getpass("Password: ")


class Context(object):
    def __init__(self, options):
        # Connect to the Hsm remotely
        self.hsm = YubiHsm.connect(_get_server_url())

        # Create an authenticated/encrypted session with given credentials
        password = _get_password()
        self.session = self.hsm.create_session_derived(
                int(options.session_id), password)
        del(password)

        # Retrieve key
        self.key = AsymmetricKey(self.session, int(options.key_id))

    def close(self):
        self.session.close()
        self.hsm.close()

    def do_info(self, key_type):
        pub_key = self.key.get_public_key()
        pub_key_pem = pub_key.public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo)
        pub_key_der = pub_key.public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo)
        pub_key_rpb = bytes(0)

        pub_key_der_hex = binascii.b2a_hex(pub_key_der).decode("UTF-8")
        pub_key_rpb_hex = binascii.b2a_hex(pub_key_rpb).decode("UTF-8")

        json.dump({
            "pub_key_pem": pub_key_pem.decode("UTF-8"),
            "pub_key_der": pub_key_der_hex,
            "pub_key_rpb": pub_key_rpb_hex,
        }, sys.stdout)

    def do_sign(self, key_type, digest):
        # Hand craft the packet for signature request.
        # The official API 'sign_ecdsa' expects data and a hash function
        # whereas we need to pass directly the digest
        if key_type == "rsa":
            mgf = getattr(ALGORITHM, "RSA_MGF1_SHA256")
            msg = struct.pack("!HBH", self.key.id, mgf, 32) + digest
            signature = self.session.send_secure_cmd(COMMAND.SIGN_PSS, msg)
        elif key_type == "ecdsa":
            msg = struct.pack("!H%ds" % len(digest), self.key.id, digest)
            signature = self.session.send_secure_cmd(COMMAND.SIGN_ECDSA, msg)

        signature_hex = binascii.b2a_hex(signature).decode("UTF-8")

        json.dump({
            "signature": signature_hex,
        }, sys.stdout)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("action",
            choices=["sign", "info"],
            help="Action")

    parser.add_argument("digest",
            nargs="?",
            help="Digest of data to sign")

    parser.add_argument("-s", "--session",
            dest="session_id",
            default=_get_session_id(),
            metavar="SID",
            help="Id of the session to use for communicating with HSM")

    parser.add_argument("-k", "--key",
            dest="key_id",
            metavar="KID",
            help="Id of the key to use")

    parser.add_argument("-t", "--type",
            dest="key_type",
            choices=["ecdsa", "rsa"],
            metavar="TYPE",
            help="Type of the key to use")

    options = parser.parse_args()

    ctx = Context(options)

    if options.action == "info":
        ctx.do_info(options.key_type)
    elif options.action == "sign":
        ctx.do_sign(options.key_type, binascii.a2b_hex(options.digest))

    ctx.close()

if __name__ == "__main__":
    main()
