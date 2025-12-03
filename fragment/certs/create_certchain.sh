#!/usr/bin/env bash
# Adopted from https://github.com/Azure/azure-cli-extensions/tree/47cc21964398212a09c730a8051610e0a28ba6f1/src/confcom/samples/certs


# Following guide from: https://www.golinuxcloud.com/openssl-create-certificate-chain-linux/

set -xe

RootPath=`realpath $(dirname $0)`
cd $RootPath

rm -rf $RootPath/rootCA
mkdir -p $RootPath/rootCA/{certs,crl,newcerts,private,csr}

echo 1000 > $RootPath/rootCA/serial

echo 0100 > $RootPath/rootCA/crlnumber

touch $RootPath/rootCA/index.txt

# generate root key
openssl genrsa -out $RootPath/rootCA/private/ca.key.pem 4096
chmod 400 $RootPath/rootCA/private/ca.key.pem

# view the key
# openssl rsa -noout -text -in $RootPath/rootCA/private/ca.key.pem

# generate root cert
openssl req -config openssl_root.cnf -key $RootPath/rootCA/private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out $RootPath/rootCA/certs/ca.cert.pem -subj "/CN=skr-ca"

# change permissions on root key so it's not globally readable
chmod 444 $RootPath/rootCA/certs/ca.cert.pem

# verify root cert
openssl x509 -noout -text -in $RootPath/rootCA/certs/ca.cert.pem

# create signing key
rm -rf $RootPath/signer
mkdir -p $RootPath/signer/{certs,crl,newcerts,private,csr}
openssl ecparam -out $RootPath/signer/private/skr.key.pem -name secp384r1 -genkey
openssl pkcs8 -topk8 -nocrypt -in $RootPath/signer/private/skr.key.pem -out $RootPath/signer/private/ec_p384_private.pem

chmod 400 $RootPath/signer/private/skr.key.pem
# create csr for signer
openssl req -key $RootPath/signer/private/skr.key.pem -new -sha384 -out $RootPath/signer/csr/skr.csr.pem -batch -subj "/CN=skr"

# sign signer cert with root key
openssl ca -config openssl_root.cnf -days 375 -notext -md sha384 -in $RootPath/signer/csr/skr.csr.pem -out $RootPath/signer/certs/skr.cert.pem -batch
# print the cert
# openssl x509 -noout -text -in $RootPath/signer/certs/skr.cert.pem

# make a public key
# openssl x509 -pubkey -noout -in $RootPath/signer/certs/skr.cert.pem -out $RootPath/signer/certs/pubkey.pem

# create chain file
cat $RootPath/signer/certs/skr.cert.pem $RootPath/rootCA/certs/ca.cert.pem > $RootPath/signer/certs/skr.chain.cert.pem
