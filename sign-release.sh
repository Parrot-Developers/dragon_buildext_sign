#!/bin/bash

function usage()
{
	echo "$0 <in_archive> <out_archive> <sign_script> ..."
	echo ""
	echo "Re-sign images found in a release archive"
	echo "<in_archive> : input archive"
	echo "<out_archive>: output archive"
	echo "<sign_script>: script to use for each found image"
	echo "...          : additional arguments for <sign_script>"
}

if [ "$1" = "-h" -o "$1" = "--help" ]; then
	usage
	exit 0
fi

if [ "$#" -lt 3 ]; then
	usage
	exit 1
fi

set -e

readonly IN_ARCHIVE=$1
readonly OUT_ARCHIVE=$2
readonly SIGN_SCRIPT=$3
shift
shift
shift

# Setup temp dir that will be deleted at the end
readonly TMP_DIR=$(mktemp -d --suffix .sign)
trap "rm -rf ${TMP_DIR}" EXIT SIGINT SIGTERM

echo "Extracting release archive ${IN_ARCHIVE}"
tar -C ${TMP_DIR} -xvf ${IN_ARCHIVE}

for image in $(ls ${TMP_DIR}/images/*.tar.gz); do
	echo "Re-sign ${image}"
	${SIGN_SCRIPT} ${image} ${image} "$@" || echo "Skipping ${image}"
done

echo "Reconstruct md5sum file"
rm -f ${TMP_DIR}/md5sum.txt
cd ${TMP_DIR} && md5sum $(find -type f) > md5sum.txt

echo "Reconstruct release archive in ${OUT_ARCHIVE}"
tar -C ${TMP_DIR} -cvf ${OUT_ARCHIVE} .
