#!/bin/bash
OUTPUT_FILE=${1}

echo "./host-sbom.sh \"${1}\""
date

echo OUTPUT_FILE: $OUTPUT_FILE

cd /tmp
nice -n 10 syft dir:/host --exclude './**/snapshots/**' --exclude './**/rootfs/**' --exclude './**/overlay2/**' --exclude './var/lib/kubelet/pods/**' -o json > $OUTPUT_FILE
