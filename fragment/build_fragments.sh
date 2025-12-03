#!/usr/bin/env bash

SKR_IMAGE_NAME=${SKR_IMAGE_NAME:-skr}
ENCFS_IMAGE_NAME=${ENCFS_IMAGE_NAME:-encfs}

if [[ "$SKR_IMAGE_NAME" != *":"* ]]; then
    SKR_IMAGE_NAME="${SKR_IMAGE_NAME}:latest"
fi
if [[ "$ENCFS_IMAGE_NAME" != *":"* ]]; then
    ENCFS_IMAGE_NAME="${ENCFS_IMAGE_NAME}:latest"
fi

if [ -n "$REGISTRY" ]; then
    SKR_IMAGE_NAME="${REGISTRY}/${SKR_IMAGE_NAME}"
    ENCFS_IMAGE_NAME="${REGISTRY}/${ENCFS_IMAGE_NAME}"
fi

echo "skr: ${SKR_IMAGE_NAME}"
echo "encfs: ${ENCFS_IMAGE_NAME}"

if ! which sign1util > /dev/null 2>&1; then
    echo "sign1util not found in PATH."
    exit 1
fi

set -e
cd `dirname $0`

CHAIN="certs/signer/certs/skr.chain.cert.pem"
KEY="certs/signer/private/ec_p384_private.pem"

if [ ! -f ${CHAIN} ] || [ ! -f ${KEY} ]; then
    echo "Generating certs"
    ./certs/create_certchain.sh
fi

ISSUER_DID=$(sign1util did-x509 -chain certs/signer/certs/skr.chain.cert.pem)
echo "iss: ${ISSUER_DID}"

if ! docker image inspect $SKR_IMAGE_NAME > /dev/null 2>&1; then
    echo "Image $SKR_IMAGE_NAME not found."
    exit 1
fi

FEED=mcr.microsoft.com/aci/skr
echo "feed: ${FEED}"

function build_and_patch() {
    local name=$1
    local image=$2

    echo "Building fragment for ${name}: ${image}"
    az confcom acifragmentgen \
        --svn 1 \
        --namespace microsoft_confidential_sidecars \
        --feed ${FEED} \
        --image ${image} \
        --no-print \
        --output-filename "${name}_fragment" # produces ${name}_fragment.rego and ${name}_fragment.rego.cose
    mv "${name}_fragment.rego" "${name}_fragment.orig.rego"

    patch --batch "${name}_fragment.orig.rego" "${name}_fragment.rego.patch" -o "${name}_fragment.rego"

    sign1util create -algo ES384 -chain ${CHAIN} -claims "${name}_fragment.rego" -key ${KEY} -out "${name}_fragment.rego.cose" -salt zero \
        -feed ${FEED} -content-type application/unknown+rego \
        -issuer ${ISSUER_DID}

    output=$(oras attach ${image} \
		--artifact-type application/x-ms-ccepolicy-frag \
		"./${name}_fragment.rego.cose:application/cose-x509+rego" \
        --format json)

    reference=$(echo "$output" | jq -r '.reference')
    echo -e "Fragment: \x1b[1;32m${reference}\x1b[0m"

    az confcom acifragmentgen --generate-import \
        -p ./${name}_fragment.rego.cose --minimum-svn 1 --fragments-json ${name}_import_rules.json
}

build_and_patch skr "${SKR_IMAGE_NAME}"
build_and_patch encfs "${ENCFS_IMAGE_NAME}"

if ! docker image inspect $ENCFS_IMAGE_NAME > /dev/null 2>&1; then
    echo "Image $ENCFS_IMAGE_NAME not found."
    exit 1
fi
