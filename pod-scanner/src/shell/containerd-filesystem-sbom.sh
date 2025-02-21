#!/bin/bash
CONTAINER_ID=${1}
IMAGE=${2}
SNAPSHOT_FOLDER=${3}
SBOM_FILE=${4}
SIZE_FILE=${5}

echo "./containerd-filesystem-sbom.sh \"${1}\" \"${2}\" \"${3}\" \"${4}\" \"${5}\""
date

echo CONTAINER_ID: $CONTAINER_ID
echo IMAGE: $IMAGE
echo SNAPSHOT_FOLDER: $SNAPSHOT_FOLDER
echo SBOM_FILE: $SBOM_FILE
echo SIZE_FILE: $SIZE_FILE

cleaned_container_id="${CONTAINER_ID#containerd://}"

SOURCE_NAME=${IMAGE%%[:@]*}

# Extract after ':' or '@', only if the delimiter exists
if [[ "$IMAGE" == *[:@]* ]]; then
    SOURCE_VERSION="${IMAGE##*[:@]}"
else
    SOURCE_VERSION=""
fi

echo SOURCE_NAME: $SOURCE_NAME
echo SOURCE_VERSION: $SOURCE_VERSION
rm -f $SBOM_FILE
rm -f $SIZE_FILE

current_config=`cat /hostmounts | grep ${cleaned_container_id}`
lower_dir_path=$(echo "$current_config" | sed -n 's/.*lowerdir=\([^,]*\),upperdir=.*/\1/p')

cd /tmp
rm -fr tmpcontainer
mkdir tmpcontainer

image_size=0
IFS=':' read -ra paths <<< "$lower_dir_path" # Split the string into an array
for (( idx=${#paths[@]}-1 ; idx>=0 ; idx-- )); do
    host_path=${paths[idx]}
    echo "$host_path"
    tmp_path="/host${host_path}"
    if [ ! -d "$tmp_path" ]; then
      #Directory doesn't exist, try with snapshot folder
      tmp_path="${SNAPSHOT_FOLDER}/${host_path}"
    fi

    echo Copying $tmp_path to folder
    cp -rf $tmp_path tmpcontainer
    echo Calculate size of $tmp_path
    tmp_size=`du -skbl $tmp_path 2>/dev/null | awk '{print $1}'`
    ((image_size+=tmp_size))
done
echo $image_size > $SIZE_FILE
echo Total size of image: $image_size kB, written to $SIZE_FILE
echo Start generating SBOM
nice -n 10 syft dir:tmpcontainer/fs --source-name "${SOURCE_NAME}" --source-version "${SOURCE_VERSION}" -o json > $SBOM_FILE
echo Result written to $SBOM_FILE
rm -rf tmpcontainer
