#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set -e

echo "There are three steps to deploying the managed HSM"
echo " - Deploy the HSM in azure"
echo " - Create 3 keys to encrypt the security domain"
echo " - Download the security domain and activate the HSM"

output=$(az deployment group create \
    --name "confidential-sidecars-managed-hsm" \
    --resource-group $RESOURCE_GROUP \
    --template-file managedHSM.bicep \
    --parameters ./managedHSM.bicepparam \
    --query "{admins: properties.outputs.admins.value, name: properties.outputs.name.value}" \
    --output json)

admin_ids=$(echo $output | jq -r '.admins')
hsm_name=$(echo $output | jq -r '.name')

echo "HSM deployed, creating keys"

# Generating three certificates used to activate the managed HSM
script_dir=$(dirname $(realpath ${BASH_SOURCE[0]}))
cert_dir=$script_dir/hsm_certs
mkdir -p $cert_dir
pushd $cert_dir
for i in {0..2}; do
    openssl req -newkey rsa:2048 -nodes -keyout cert_$i.key -x509 -days 365 -out cert_$i.cer
done
popd

echo "Keys created, downloading security domain"

az keyvault security-domain download \
    --hsm-name $hsm_name \
    --sd-wrapping-keys $cert_dir/cert_0.cer $cert_dir/cert_1.cer $cert_dir/cert_2.cer \
    --sd-quorum 2 \
    --security-domain-file $cert_dir/$hsm_name-SD.json

for admin_id in $admin_ids; do
    az keyvault role assignment create \
        --hsm-name $hsm_name \
        --role "Managed HSM Crypto User" \
        --assignee $admin_id \
        --scope /keys
done
