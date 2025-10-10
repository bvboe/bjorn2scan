#!/bin/bash
IMAGE=$1
DIRECTORY=$2
APP_VERSION=$3

# Helper script to build and release an image
echo Build image $IMAGE from directory $DIRECTORY with version $APP_VERSION

cd $DIRECTORY
docker buildx create --name k8s-scanner-builder --use --driver docker-container
docker buildx build --builder k8s-scanner-builder --platform linux/amd64,linux/arm64 --build-arg VERSION=$APP_VERSION -t $1 --push .
