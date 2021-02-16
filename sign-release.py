#!/usr/bin/env python3

# Below is the typical structure under the folder passed as 3rd argument of this script.
# i.e. <sign_workspace_dir> : the path to the directory that contains all the required
# tools to re-sign a release, as part of the prod_signature promotion step.
#
# .
# ├── alchemy
# │   └── scripts
# │       └── sparse.py
# ├── dragon_buildext_sign
# │   ├── buildext.py
# │   ├── sign.py
# │   ├── sign-release.py
# │   └── yhsm.py
# ├── JKS_PRODUCT=anafi2,JKS_VARIANT=classic
# │   ├── alchemy.tar
# │   ├── dragon_buildext_sign.tar
# │   ├── product.tar
# │   ├── vendor_tools.tar
# │   └── out
# │       └── anafi2-classic
# │           ├── images
# │           │   ├── anafi2-classic-reflash-dev-osonly.tar.gz
# │           │   ├── anafi2-classic-update-dev-osonly.tar.gz
# │           │   └── carpet_lib.tgz
# │           ├── release-anafi2-classic-7.0.0-beta44.tar
# │           └── staging-host
# │               └── usr
# │                   └── bin
# │                       └── mkimage
# ├── product
# │   ├── classic
# │   │   └── config
# │   │       └── product_config.json
# │   ├── common
# │   ├── hil
# │   ├── pc
# │   └── scripts
# │       ├── sign-bootloader-prod.sh
# │       └── sign-image-prod.sh
# └── vendor_tools
#     └── 1.1.0-1
#         └── usr
#             └── local
#                 └── bin
#                     └── hisi-secure-boot

import argparse
import json
import logging
import os
import shutil
import sys
import tarfile
import tempfile

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'dragon_citools'))
from citools_utils import ShellWrapper, find_file, find_dir
shell_wrapper = ShellWrapper()

USAGE = (
    "sign-release.py <in_archive> <out_archive> <sign_workspace_dir> \n\n"
    "Script re-signing images found in a release archive \n\n"
)

# color definitions for logging
color_map = { "DEFAULT": "\033[00m", "RED": "\033[31m", "GREEN": "\033[32m", "YELLOW": "\033[33m" }

#===============================================================================
#===============================================================================
def call_script(script_name, args):
    cmd = [script_name]
    if args:
        cmd.extend(args)
    shell_wrapper.exec_cmd(" ".join(cmd))

#===============================================================================
# Reconstruct release archive.
#===============================================================================
def reconstruct_release_archive(options, cwd):
    logging.info("Reconstruct release archive in %s", options.out_archive)
    cmd = ["tar", "-C", cwd, "-cvf", options.out_archive, "."]
    shell_wrapper.exec_cmd(" ".join(cmd), cwd=cwd)

#===============================================================================
# Reconstruct md5sum file.
#===============================================================================
def reconstruct_md5sum_file(cwd):
    logging.info("Reconstruct md5sum file")
    os.remove(os.path.join(cwd, "md5sum.txt"))
    cmd = ["md5sum", "$(find -type f)", ">", "md5sum.txt"]
    shell_wrapper.exec_cmd(" ".join(cmd), cwd=cwd)

#===============================================================================
# Retrieve the images to sign as dictionary from the file product_config.json
#===============================================================================
def get_images_to_sign(product_config_json, variant, basedir):
    images_to_sign = {}

    images = product_config_json["signature"][variant]["images"]
    for img in images:
        in_image_path = os.path.join(basedir, img["in"])
        if os.path.isfile(in_image_path):
            if "out" in img:
                out_image_path = os.path.join(basedir, img["out"])
                images_to_sign[in_image_path] = out_image_path
            else:
                images_to_sign[in_image_path] = in_image_path

    return images_to_sign

#===============================================================================
# Retrieve build properties as dictionary from the file build.prop
#===============================================================================
def get_build_props(filename):
    with open(filename) as f:
        lines = f.readlines()

    props = {}
    for line in lines:
        line = line.strip("\n")
        fields = line.split("=", 1)  # format is <key>=<value>
        if len(fields) == 2:
            props[fields[0]] = fields[1]
    return props

#===============================================================================
# Retrieve the variant from the file build.prop
#===============================================================================
def get_variant(cwd):
    build_prop = find_file("build.prop", cwd=cwd)
    props = get_build_props(build_prop)
    return props["ro.parrot.build.variant"]

#===============================================================================
# Extract release archive.
#===============================================================================
def extract_release_archive(options, outdir):
    logging.info("Extracting release archive %s", options.in_archive)
    tar = tarfile.open(options.in_archive, 'r:')
    tar.extractall(path=outdir)
    tar.close()

#===============================================================================
# Setup logging system with given options.
#===============================================================================
def setup_log():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s" + color_map["DEFAULT"],
        stream=sys.stderr)
    logging.addLevelName(logging.CRITICAL, color_map["RED"] + "C")
    logging.addLevelName(logging.ERROR, color_map["RED"] + "E")
    logging.addLevelName(logging.WARNING, color_map["YELLOW"] + "W")
    logging.addLevelName(logging.INFO, color_map["GREEN"] + "I")
    logging.addLevelName(logging.DEBUG, "D")

#===============================================================================
# Validate options given.
#===============================================================================
def check_args(options, parser):
    if not options.in_archive.endswith('.tar') or not options.out_archive.endswith('.tar'):
        parser.error("Argument in_archive and out_archive must be valid tar archives.")

    if not os.path.isdir(options.sign_workspace_dir):
        parser.error("Argument sign_workspace_dir is not a valid directory path: '{0}'."
            .format(options.sign_workspace_dir))

#===============================================================================
# Parse command line arguments and return options.
#===============================================================================
def parse_args():
    parser = argparse.ArgumentParser(usage=USAGE)

    parser.add_argument("in_archive",
        help="input release archive that we want to re-sign the images it contains")

    parser.add_argument("out_archive",
        help="output release archive repackaged after images were re-signed")

    parser.add_argument("sign_workspace_dir",
        help="workspace where to get all the required tools to sign a release")

    options = parser.parse_args()
    check_args(options, parser)

    return options

#===============================================================================
#===============================================================================
def main():
    options = parse_args()
    setup_log()

    with tempfile.TemporaryDirectory(suffix=".sign") as tmpdir:

        extract_release_archive(options, outdir=tmpdir)

        # search build.prop file to retrieve the current variant
        variant = get_variant(cwd=tmpdir)
        if not variant:
            raise Exception("Could not retrieve variant from the input release archive.")

        # search the product directory to actually look for the signature script
        product_dir = find_dir("product", cwd=options.sign_workspace_dir)
        if not product_dir:
            raise Exception("Could not find the product directory in the sign promotion workspace.")

        # load product_config.json
        product_config = find_file("product_config.json", cwd=tmpdir)
        with open(product_config) as json_conf:
            product_config_json = json.load(json_conf)

        if "signature" in product_config_json and variant in product_config_json["signature"]:
            # search the signature script under product based on script name found in product config
            signature_script = find_file(product_config_json["signature"][variant]["script"], cwd=product_dir)
            if not signature_script:
                raise Exception("Could not find the signature script based on the provided product.")

            # search product_config.json file to get the list of images that we need to re-sign,
            images_to_sign = get_images_to_sign(product_config_json, variant, basedir=os.path.join(tmpdir, "images"))

            # re-sign the images of the release with the prod keys
            for image in images_to_sign:
                logging.info("Re-sign %s", image)
                call_script(signature_script, [image, images_to_sign[image], options.sign_workspace_dir])

            # reconstruct md5sum file and final/signed release archive
            reconstruct_md5sum_file(cwd=tmpdir)
            reconstruct_release_archive(options, cwd=tmpdir)

        else:
            logging.info("No signature/variant block in product_config.json, skipping re-sign of release %s", options.in_archive)
            # copy input release archive to allow its publication in prod mode even if not re-signed
            shutil.copyfile(options.in_archive, options.out_archive)

#===============================================================================
#===============================================================================
if __name__ == "__main__":
    main()
