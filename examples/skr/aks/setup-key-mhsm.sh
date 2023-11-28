#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# This script creates a RSA key in MHSM with a release policy, then downloads
# the public key and saves the key info

if [ $# -ne 2 ] ; then
	echo "Usage: $0 <key-name> <mhsm-name>"
	exit 1
fi

key_name=$1
mhsm_name=$2

response=$(curl --silent --write-out "\n%{http_code}" -X GET https://${mhsm_name}.managedhsm.azure.net)
if [ $(echo "$response" | tail -n1) -eq 401 ]; then
  echo "......MHSM endpoint OK"
else
  echo "Request failed with status code $(echo "$response" | tail -n1)"
  echo "MHSM ${mhsm_name} doesn't exist. Please follow instructions to set it up first:"
  echo ""
  echo "https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli"
  exit 1
fi

if [ -z "${MAA_ENDPOINT}" ]; then
	echo "Error: Env MAA_ENDPOINT is not set. Please set up your own MAA instance or select from a region where MAA is offered (e.g. sharedeus2.eus2.attest.azure.net):"
	echo ""
	echo "https://azure.microsoft.com/en-us/explore/global-infrastructure/products-by-region/?products=azure-attestation"
	exit 1
fi

if [ -z "${MANAGED_IDENTITY}" ]; then
	echo "Error: Env MANAGED_IDENTITY is not set. Please assign principal ID of the managed identity that will have read access to the key. To create a managed identity:"
	echo "   az identity create -g <resource-group-name> -n <identity-name>"
	exit 1
fi

policy_file_name="${key_name}-release-policy.json"

echo { \"anyOf\":[ { \"authority\":\"https://${MAA_ENDPOINT}\", \"allOf\":[ > ${policy_file_name}
echo '{"claim":"x-ms-attestation-type", "equals":"sevsnpvm"},' >> ${policy_file_name}

# if [[ -z "${GUEST_IMAGE_MEASUREMENT}" ]]; then
# 	echo "Warning: Env GUEST_IMAGE_MEASUREMENT is not set. To better protect your key, consider adding it to your key release policy"
# else
# 	echo {\"claim\":\"x-ms-sevsnpvm-launchmeasurement\", \"equals\":\"${GUEST_IMAGE_MEASUREMENT}\"}, >> ${policy_file_name}
# fi

# if [[ -z "${WORKLOAD_MEASUREMENT}" ]]; then
# 	echo "Warning: Env WORKLOAD_MEASUREMENT is not set. To better protect your key, consider adding it to your key release policy"
# else
# 	echo {\"claim\":\"x-ms-sevsnpvm-hostdata\", \"equals\":\"${GUEST_IMAGE_MEASUREMENT}\"}, >> ${policy_file_name}
# fi

echo '] } ], "version":"0.2" }' >> ${policy_file_name}
echo "......Generated key release policy ${policy_file_name}"

# Create RSA key
az keyvault key create --id https://${mhsm_name}.managedhsm.azure.net/keys/${key_name} --ops wrapKey unwrapkey encrypt decrypt --kty RSA-HSM --size 3072 --exportable --policy ${policy_file_name}
echo "......Created RSA key in ${mhsm_name}"

# Download the public key
public_key_file=${key_name}-pub.pem
rm -f ${public_key_file}
az keyvault key download --hsm-name ${mhsm_name} -n ${key_name} -f ${public_key_file}
echo "......Downloaded the public key to ${public_key_file}"

# Assign access role to MSI
az keyvault role assignment create --hsm-name ${mhsm_name} --assignee ${MANAGED_IDENTITY} --role "Managed HSM Crypto User" --scope /keys/${key_name} | true
echo "......Assigned key read permission to managed identity ${MANAGED_IDENTITY}"

# generate key info file
key_info_file=${key_name}-info.json
echo {  > ${key_info_file}
echo \"public_key_path\": \"${public_key_file}\", >> ${key_info_file}
echo \"kms_endpoint\": \"${mhsm_name}.managedhsm.azure.net\", >> ${key_info_file}
echo \"attester_endpoint\": \"${MAA_ENDPOINT}\" >> ${key_info_file}
echo }  >> ${key_info_file}
echo "......Generated key info file ${key_info_file}"
echo "......Key setup successful!"