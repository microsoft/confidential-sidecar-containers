#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

DIR_OF_THIS_FILE=$(cd $(dirname $0); pwd)/

function usage {
    set +x
    echo "Usage: $0 <AZURE_RESOURCE_GROUP> <DOCKER_REGISTRY_NAME> <DEPLOY_ID>"
    echo "You need to login to Azure CLI and set default subscription before run this script by \`az account set --subscription <subscription>\`"
    echo "Options:"
    echo "  -h, --help  Show this help message and exit"
}

# Check for the three required parameters
if [[ $# -lt 3 ]]; then
    echo $#
    usage
    exit 1
fi

AZURE_RESOURCE_GROUP="$1"
DOCKER_REGISTRY_NAME="$2"
DEPLOY_ID="$3"

while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -h|--help)
        usage
        exit 0
        ;;
        *)
        # Skip any other options
        ;;
    esac
    shift # past argument or value
done

# Build docker image
DOCKER_IMAGE_NAME=attestation-container-dev
DOCKER_IMAGE_VERSION=$DEPLOY_ID

cd $DIR_OF_THIS_FILE
cd ../../ # Go to project root
docker build -t $DOCKER_IMAGE_NAME -f docker/attestation-container/Dockerfile . --build-arg variant=dev

# Push docker image
az acr login --name $DOCKER_REGISTRY_NAME
LOGIN_SERVER=$(az acr show --name $DOCKER_REGISTRY_NAME --query loginServer --output tsv  | sed 's/\r//g')
DOCKER_IMAGE="$LOGIN_SERVER/$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_VERSION"
docker tag $DOCKER_IMAGE_NAME $DOCKER_IMAGE
docker push $DOCKER_IMAGE
function clean_up_docker_image {
    az acr repository delete --name $DOCKER_REGISTRY_NAME --image $DOCKER_IMAGE_NAME:$DOCKER_IMAGE_VERSION --yes
}
function clean_up {
    clean_up_docker_image
}
trap clean_up EXIT

# Deploy
cd $DIR_OF_THIS_FILE
CONTAINER_GROUP_NAME="attestation-container-ci-$DEPLOY_ID"
DEPLOYMENT_NAME=$CONTAINER_GROUP_NAME
# Do not use unsafe_ci_template.json in production. It's not secure.
az deployment group create --resource-group $AZURE_RESOURCE_GROUP --name $DEPLOYMENT_NAME --template-file unsafe_ci_template.json --parameter containerGroupName="$CONTAINER_GROUP_NAME" dockerImage="$DOCKER_IMAGE"
function clean_up_container_group {
    az container delete --resource-group $AZURE_RESOURCE_GROUP --name $DEPLOYMENT_NAME --yes
}
# Update clean_up definition
function clean_up {
    clean_up_docker_image
    clean_up_container_group
}

# Test
az container exec --resource-group $AZURE_RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name attestation-container-dev --exec-command 'attest.test -test.v'
az container exec --resource-group $AZURE_RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name attestation-container-dev --exec-command 'common.test --testdata-dir /test_security_context -test.v'
az container exec --resource-group $AZURE_RESOURCE_GROUP --name $CONTAINER_GROUP_NAME --container-name attestation-container-dev --exec-command 'attestation-container.test -addr /mnt/uds/sock -test.v'

