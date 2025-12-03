#!/usr/bin/env bash

if [ -z "$REGISTRY" ]; then
    echo "REGISTRY environment variable is not set. Do setup-envs.sh first."
    exit 0
fi

if ! docker image inspect skr > /dev/null 2>&1; then
    echo "Docker image 'skr' not found. Build it first."
    exit 1
fi

if ! docker image inspect encfs > /dev/null 2>&1; then
    echo "Docker image 'encfs' not found. Build it first."
    exit 1
fi

az acr login --name "$REGISTRY"
docker tag skr "$REGISTRY/$SKR_IMAGE_NAME"
docker tag encfs "$REGISTRY/$ENCFS_IMAGE_NAME"

function oras_clean() {
    local image_name=$1
    oras discover $REGISTRY/$image_name --artifact-type application/x-ms-ccepolicy-frag --format json | jq -r '.manifests[].reference' | xargs --no-run-if-empty -n 1 oras manifest delete -f
}
oras_clean "$SKR_IMAGE_NAME"
oras_clean "$ENCFS_IMAGE_NAME"

docker push "$REGISTRY/$SKR_IMAGE_NAME"
docker push "$REGISTRY/$ENCFS_IMAGE_NAME"

if ! which oras > /dev/null 2>&1; then
    echo "oras not in PATH."
    exit 1
fi
