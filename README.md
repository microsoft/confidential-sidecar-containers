# Confidential Sidecar Containers

This repository contains the code needed to build the sidecar containers used for [confidential containers](https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-confidential-containers-on-azure/ba-p/3410394).

The code in this repository should be located at ``$GOPATH/src/microsoft/confidential-sidecar-containers``.

## Build Pipelines

These build pipelines run nightly based off of images created from the main branch of this repo. They are used to test the latest changes to the sidecar containers.

- [![Test Key Release (Latest)](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_key_release_latest.yml/badge.svg)](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_key_release_latest.yml)
- [![Test Encrypted Filesystem (Latest)](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_encrypted_filesystem_latest.yml/badge.svg)](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_encrypted_filesystem_latest.yml)
- [![Test Attestation](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_attestation.yml/badge.svg)](https://github.com/microsoft/confidential-aci-examples/actions/workflows/test_attestation.yml)

## Secure key release (SKR) sidecar

The ``docker/skr/build.sh`` script builds all necessary Go tools for secure key release as standalone binaries and creates a Docker image that contains them so that it
can be used as a sidecar container. The skr sidecar container is executed by calling the script ``skr.sh``. More information about the skr API can be found [here](cmd/skr/README.md).

The skr sidecar can be queried by application containers hosted in the same pod (or container group) for retrieving attestation reports and for releasing secrets from managed HSM key vaults.

The ``examples/skr`` shows an example of how the skr sidecar can be deployed and tested within a confidential container group on ACI.

### Fetching an attestion report

``tools/get-snp-report`` provides a tool which will return an SNP attestation report from the AMD PSP via linux IOCTLs. it can take a hex encoded report data value on the command line. The output is a hex encoded binary object. If piped through hex2report it can be read by people. There are two implementations inside the one tool to support the different IOCTLs requirements between linux 5.15 and 6.1 and later.

### Third-party code

The [AES unwrap key without padding method](https://github.com/NickBall/go-aes-key-wrap/blob/master/keywrap.go) code was modified to implement the aes key unwrap with padding method.

## Encrypted Filesystem sidecar

The ``docker/encfs/build.sh`` script builds all necessary Go tools (for encrypted filesystems) and creates a Docker image that contains them so that it can be used as a sidecar container. The encrypted filesystem sidecar container is executed by calling the script ``encfs.sh`` with a base64-encoded string as an environment variable or a command-line argument. The entry point to the sidecar is the [remotefs tool](cmd/remotefs/README.md) which leverages the [azmount tool](cmd/azmount/README.md).

The encrypted filesystem sidecar uses the SKR library to release key material from Azure Key Vault instances required for mounting the encrypted filesystems required by the application.

The ``examples/encfs`` shows an example of how the encrypted filesystem sidecar can be deployed within a confidential container group on ACI.

## Dependencies

- Golang 1.19 or later
- Docker
- GCC 9.4.0 or later

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
<https://cla.microsoft.com>.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
