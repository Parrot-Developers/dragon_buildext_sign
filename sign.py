#!/usr/bin/env python3

import argparse
import binascii
import io
import json
import os
import requests
import subprocess
import tarfile
import tempfile

from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import pkcs1_15, DSS

#===============================================================================
# Compute the RPB form of a RSA public key
# pub_key must be a RsaKey object obtained with the Cryptodome.PublicKey.RSA
# functions.
# Return bytes containing the RPB representation of the public key
#===============================================================================
def compute_rsa_pub_key_rpb(pub_key):
    def _egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def _modinv(a, m):
        g, x, _ = _egcd(a, m)
        if g != 1:
            raise Exception("No modular inverse")
        return x % m

    # RPB does not handle values other than 3 for e
    if pub_key.e != 3:
        raise Exception("Public exponent (e) must be 3, not %s" % pub_key.e)
    nbits = pub_key.size_in_bits()
    n0inv = (1 << 32) - _modinv(pub_key.n, 1 << 32)
    rr = (2 ** (2 * nbits)) % pub_key.n

    # Fill a struct with the folowing C-format:
    # #define RSANUMBYTES 256           /* 2048 bit key length */
    # #define RSANUMWORDS (RSANUMBYTES  / sizeof(uint32_t))
    # typedef struct RSAPublicKey {
    #     int len;                  /* Length of n[] in number of uint32_t */
    #     uint32_t n0inv;           /* -1 / n[0] mod 2^32 */
    #     uint32_t n[RSANUMWORDS];  /* modulus as little endian array */
    #     uint32_t rr[RSANUMWORDS]; /* R^2 as little endian array */
    # } RSAPublicKey;
    nwords = nbits // 32
    nbytes = nbits // 8
    rpb = bytearray()
    rpb += nwords.to_bytes(4, "little")
    rpb += n0inv.to_bytes(4, "little")
    rpb += pub_key.n.to_bytes(nbytes, "little")
    rpb += rr.to_bytes(nbytes, "little")
    return bytes(rpb)

class Provider(object):
    def get_info(self):
        raise NotImplementedError

    def sign(self, digest):
        raise NotImplementedError

#===============================================================================
# Local Rsa key signing
#===============================================================================
class RsaLocal(Provider):
    def __init__(self, key):
        with open(key, "rb") as fin:
            self.priv_key = RSA.import_key(fin.read())
        self.pub_key = self.priv_key.publickey()
        self.der = self.pub_key.exportKey(format="DER")
        self.rpb = compute_rsa_pub_key_rpb(self.pub_key)

    def get_info(self):
        return {
            "pub_key_der": binascii.b2a_hex(self.der).decode("UTF-8"),
            "pub_key_rpb": binascii.b2a_hex(self.rpb).decode("UTF-8"),
        }

    def sign(self, msg_hash):
        scheme = pkcs1_15.new(self.priv_key)
        signature = scheme.sign(msg_hash)
        signature_hex = binascii.b2a_hex(signature).decode("UTF-8")
        return signature_hex


#===============================================================================
# Local Ecdsa key signing
#===============================================================================
class EcdsaLocal(Provider):
    def __init__(self, key):
        with open(key, "rb") as fin:
            self.priv_key = ECC.import_key(fin.read())
        self.pub_key = self.priv_key.public_key()
        self.der = self.pub_key.export_key(format="DER")

    def get_info(self):
        return {
            "pub_key_der": binascii.b2a_hex(self.der).decode("UTF-8"),
            "pub_key_rpb": "",
        }

    def sign(self, msg_hash):
        scheme = DSS.new(self.priv_key, "fips-186-3", encoding="der")
        signature = scheme.sign(msg_hash)
        signature_hex = binascii.b2a_hex(signature).decode("UTF-8")
        return signature_hex


#===============================================================================
# Remote signing
#===============================================================================
class CryptoRemote(Provider):
    def __init__(self, url, key):
        self.url = url
        self.key = key

    def get_info(self):
        response = requests.get(self.url, params={
            "action": "info", "key": self.key})
        response.raise_for_status()
        return response.json()

    def sign(self, msg_hash):
        digest_hex = msg_hash.hexdigest()
        response = requests.get(self.url, params={
            "action": "sign", "key": self.key, "input": digest_hex})
        response.raise_for_status()
        return response.json()["signature"]


#===============================================================================
# Rsa remote signing
#===============================================================================
class RsaRemote(CryptoRemote):
    _DEFAULT_SERVER = "https://noserver.parrot.biz"

    def __init__(self, key):
        server = os.environ.get("RSA_REMOTE_SERVER", self._DEFAULT_SERVER)
        url = server + "/rsaremote/cgi-bin/rsaremote.cgi"
        super().__init__(url, key)


#===============================================================================
# Ecdsa remote signing
#===============================================================================
class EcdsaRemote(CryptoRemote):
    _DEFAULT_SERVER = "https://noserver.parrot.biz"

    def __init__(self, key):
        server = os.environ.get("ECDSA_REMOTE_SERVER", self._DEFAULT_SERVER)
        url = server + "/ecdsaremote/cgi-bin/ecdsaremote.cgi"
        super().__init__(url, key)


#===============================================================================
# Ecdsa remote signing with yubi HSM
#===============================================================================
class EcdsaYhsm(Provider):
    _YHSM = os.path.join(os.path.dirname(__file__), "yhsm.py")
    def __init__(self, key):
        self.key = key

    def get_info(self):
        cmd = [
            EcdsaYhsm._YHSM,
            "-k", self.key,
            "-t", "ecdsa",
            "info",
        ]
        result = subprocess.check_output(cmd, universal_newlines=True)
        return json.loads(result)

    def sign(self, msg_hash):
        digest_hex = msg_hash.hexdigest()
        cmd = [
            EcdsaYhsm._YHSM,
            "-k", self.key,
            "-t", "ecdsa",
            "sign", digest_hex,
        ]
        result = subprocess.check_output(cmd, universal_newlines=True)
        return json.loads(result)["signature"]


#===============================================================================
# Ecdsa Remote signing with AWS kms:
# https://aws.amazon.com/kms/
#===============================================================================
class EcdsaAwsKms(Provider):
    def __init__(self, key):
        import boto3
        self.kms_client = boto3.client("kms")
        self.key = key

    def get_info(self):
        response = self.kms_client.get_public_key(KeyId=self.key)
        pubkey = response["PublicKey"]
        return {
            "pub_key_der": binascii.b2a_hex(pubkey).decode("UTF-8"),
            "pub_key_rpb": "",
        }

    def sign(self, msg_hash):
        digest = msg_hash.digest()
        response = self.kms_client.sign(KeyId=self.key,
                MessageType="DIGEST",
                Message=digest,
                SigningAlgorithm="ECDSA_SHA_512")
        signature = response["Signature"]

        return binascii.b2a_hex(signature).decode("UTF-8")


#===============================================================================
# Compute the final hash value which will used to sign the update archive.
# 'archive' is a path to an uncompressed tar archive containing the files
#           to hash
# 'filenames' is a list of archive members whose contents will be hashed with
#             hash_func.
# 'pub_key_der' is the ASN.1 representation of the public key as bytes
# 'pub_key_rpb' is a the public key in a pre-computed form (RPB)
# 'hash_func' hash function to use (SHA256 or SHA512)
# The hash is returned as a SHAxHash object.
#
# Each file specified is hashed separately, then each hash is concatenated
# in a new hash. During verification we can then ignore order in the archive
# and re-compute the hash without the need for keeping in ram the complete
# archive. The archive can be scanned sequentially, each members being
# hashed and concatenated at the end. Only intermediate hash need to be
# stored not complete files.
#===============================================================================
def compute_final_hash(archive, filenames, pub_key_der, pub_key_rpb, hash_func):
    _hash = hash_func.new()
    tarfd = tarfile.open(archive, "r:")
    for filename in filenames:
        _hash.update(hash_func.new(tarfd.extractfile(filename).read()).digest())
    tarfd.close()
    _hash.update(";".join(filenames).encode("UTF-8"))
    _hash.update(pub_key_der)
    _hash.update(pub_key_rpb)
    return _hash


#===============================================================================
# Generate the contents of the signature file to add in the archive.
# 'archive' is the path to an uncompressed archived
# 'filenames' is a list of archive members whose contents are covered by the
#             signature
# 'pub_key_der_hex' hex string of the ASN.1 DER representation of the public key
# 'pub_key_rpb_hex' hex string of the RPB representation of the public key
# 'signature_hex' hex string of the PKCS#1 v1.5 signature blob for rsa
#                 or DSS signature for ecdsa
#===============================================================================
def generate_signature_contents(filenames,
        pub_key_der_hex, pub_key_rpb_hex, signature_hex):
    buf = io.StringIO()
    buf.write("filenames=%s\n" % ";".join(filenames))
    buf.write("pub_key_der=%s\n" % pub_key_der_hex)
    buf.write("pub_key_rpb=%s\n" % pub_key_rpb_hex)
    buf.write("signature=%s\n" % signature_hex)
    return buf.getvalue()


#===============================================================================
# Add the signature file in the archive.
#===============================================================================
def add_signature_file(archive, name, signature_contents):
    tmpfd = tempfile.NamedTemporaryFile(mode="w", delete=False)
    try:
        tmpfd.write(signature_contents)
        tmpfd.close()

        tarfd = tarfile.open(archive, "a:", format=tarfile.USTAR_FORMAT)
        if name in tarfd.getnames():
            raise FileExistsError()
        tarfd.add(tmpfd.name, name)
        tarfd.close()
    finally:
        os.unlink(tmpfd.name)


#===============================================================================
# Sign an archive
#===============================================================================
def sign_archive(archive, name, filenames, provider, hash_func):
    info = provider.get_info()

    pub_key_der_hex = info["pub_key_der"]
    pub_key_rpb_hex = info["pub_key_rpb"]
    pub_key_der = binascii.a2b_hex(pub_key_der_hex)
    pub_key_rpb = binascii.a2b_hex(pub_key_rpb_hex)

    _hash = compute_final_hash(archive, filenames,
            pub_key_der, pub_key_rpb, hash_func)

    signature_hex = provider.sign(_hash)

    signature_contents = generate_signature_contents(filenames,
            pub_key_der_hex, pub_key_rpb_hex, signature_hex)

    add_signature_file(archive, name, signature_contents)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("archive",
        help="archive to sign")

    parser.add_argument("--filenames",
        dest="filenames",
        metavar="NAMES",
        help="list of filenames to sign, separated with ';'")

    parser.add_argument("-n", "--name",
        dest="name",
        default="signature",
        help="name of signature file to create")

    parser.add_argument("-k", "--key",
        dest="key",
        help="key to use for signing")

    parser.add_argument("--hash",
        dest="hash",
        choices=["sha256", "sha512"],
        default="sha256",
        help="hash function to use")


    options = parser.parse_args()

    filenames = options.filenames.split(";")

    PROVIDERS = {
        "rsa:local:": RsaLocal,
        "rsa:remote:": RsaRemote,
        "ecdsa:local:": EcdsaLocal,
        "ecdsa:remote:": EcdsaRemote,
        "ecdsa:yhsm:": EcdsaYhsm,
        "ecdsa:aws-kms:": EcdsaAwsKms,
    }

    def get_provider():
        for (prefix, provider_cls) in PROVIDERS.items():
            if options.key.startswith(prefix):
                return provider_cls(options.key[len(prefix):])
        raise Exception("Invalid key prefix: %s" % options.key)

    provider = get_provider()

    HASH_FUNCS = {
        "sha256": SHA256,
        "sha512": SHA512,
    }
    hash_func = HASH_FUNCS[options.hash]

    sign_archive(options.archive, options.name, filenames, provider, hash_func)


if __name__ == "__main__":
    main()
