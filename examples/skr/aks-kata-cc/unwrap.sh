#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
if [ $# -ne 2 ] ; then
  echo "Usage: $0 <infile> <outfile>"
  exit 1
fi

infile=$1
outfile=$2

if [ ! -f "$infile" ]; then
  echo "Error: Input file ${infile} doesn't exist"
  exit 1
fi

if [ -z "${KEY_PROVIDER_PORT}" ]; then
  echo "Info: Env KEY_PROVIDER_PORT is not set. Use default port 50000"
  KEY_PROVIDER_PORT=50000
fi

AAA=`printf skr | base64 -w0`
ANNO=`cat ${infile}`
REQ=`echo "{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{\"dc\":{\"Parameters\":{\"attestation-agent\":[\"${AAA}\"]}},\"annotation\":\"${ANNO}\"}}" | base64 -w0`
echo KeyProviderKeyWrapProtocolInput: ${REQ}
grpcurl -plaintext -d "{\"KeyProviderKeyWrapProtocolInput\":\"${REQ}\"}" localhost:${KEY_PROVIDER_PORT} key_provider.KeyProviderService.UnWrapKey > reply.json
cat reply.json | jq -r '.KeyProviderKeyWrapProtocolOutput'  | base64 -d | jq -r '.keyunwrapresults.optsdata' | base64 -d > ${outfile}
rm reply.json
echo "Unwrapped secret saved to ${outfile}"
