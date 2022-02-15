
import os

import dragon

SIGN_SCRIPT = os.path.join(os.path.dirname(__file__), "sign.py")


#===============================================================================
# Sign an archive (that shall NOT be compressed)
# archive: file path of the archive to sign.
# filenames: file names of archive to include in signature.
# key: key name
#   rsa:local:<path>
#   rsa:remote:<name>
#   ecdsa:local:<path>
#   ecdsa:remote:<name>
#   ecdsa:yhsm:<name>
#   ecdsa:aws-kms:<key-id>
# name: name of the signature file to create.
# hash_type: hash type (sha256 or sha512)
#===============================================================================
def sign_archive(archive, filenames, key, name="signature", hash_type="sha256"):
    cmd = [
        SIGN_SCRIPT,
        "--name", name,
        "--filenames '%s'" % ";".join(filenames),
        "--key", key,
        "--hash", hash_type,
        archive,
    ]
    dragon.exec_cmd(" ".join(cmd))
