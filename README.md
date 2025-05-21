# Confidential Sidecar Containers

This repository contains the code needed to build the sidecar containers used for [confidential containers](https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-confidential-containers-on-azure/ba-p/3410394).

The code in this repository should be located at ``$GOPATH/src/microsoft/confidential-sidecar-containers``.

## Testing

[![CI](https://github.com/microsoft/confidential-sidecar-containers/actions/workflows/ci.yml/badge.svg?branch=main&event=schedule)](https://github.com/microsoft/confidential-sidecar-containers/actions/workflows/ci.yml)

Each sidecar is tested under `./tests/<sidecar_name>`.
Each directory is tested with the latest [confidential-aci-testing](https://github.com/microsoft/confidential-aci-testing) and therefore contains:

- A `docker-compose` file which describes the images to build.
These typically include a primary container image which uses the sidecar.
- A `bicep` deployment template which describes the ACI deployment.
- A `test.py` file which uses `unittest` and orchestrates, building, pushing and testing the containers.
This target is what is called in our nightly testing.

There are also supplementary files which aid the deployment:
- `deployments/` contains bicep templates and for long lived resources used by the tests, they are run once.
- `cacitesting.env` describes the deployment conditions such as which subscription and resource group to deploy to.
All required properties are populated, any unset values are optional/have default values.
Source this file (ie ```. ./cacitesting.env```) and then invoke the c-aci-testing cli to run tests.
This example leaves the deployed C-ACI container group running so it can be manually inspected via the Azure portal:
```c-aci-testing target run tests/skr --deployment-name combined-monday --no-cleanup --policy-type "allow_all"```

## Secure key release (SKR) sidecar

The ``docker/skr/build.sh`` script builds all necessary Go tools for secure key release as standalone binaries and creates a Docker image that contains them so that it can be used as a sidecar container.
The SKR sidecar container is executed by calling the script ``skr.sh``.
More information about the SKR API can be found [here](cmd/skr/README.md).

The SKR sidecar can be queried by application containers hosted in the same pod (or container group) for retrieving attestation reports and for releasing secrets from managed HSM key vaults.

The ``examples/skr/aci`` shows an example of how the SKR sidecar can be deployed and tested within a confidential container group on ACI.
The ``examples/skr/aks-kata-cc`` and ``examples/skr/maa-test-kata-cc`` shows examples of how the SKR sidecar can be deployed and tested in the Kata-based AKS preview.
Additionally, the [Kafka demo](https://github.com/microsoft/confidential-container-demos/tree/main/kafka) shows an example of how SKR can be used in the Kata-based AKS preview to send encrypted messages between containers in a Kubernetes cluster using Apache Kafka.

### Fetching an attestation report

``tools/get-snp-report`` provides a tool which will return an SNP attestation report from the AMD PSP via linux IOCTLs.
It can take a hex encoded report data value on the command line.
The output is a hex encoded binary object.
If piped through hex2report it can be read by people.
There are two implementations inside the one tool to support the different IOCTLs requirements between linux 5.15 and 6.1 and later.

An example of a container that uses this tool in Confidential ACI is located [here](https://github.com/microsoft/confidential-container-demos/blob/main/hello-world/ACI).
A Kata-based AKS version of this example is located [here](https://github.com/microsoft/confidential-container-demos/tree/main/hello-world/AKS).

### Third-party code

The [AES unwrap key without padding method](https://github.com/NickBall/go-aes-key-wrap/blob/master/keywrap.go) code was modified to implement the aes key unwrap with padding method.

## Encrypted Filesystem sidecar

The ``docker/encfs/build.sh`` script builds all necessary Go tools (for encrypted filesystems) and creates a Docker image that contains them so that it can be used as a sidecar container.
The encrypted filesystem sidecar container is executed by calling the script ``encfs.sh`` with a base64-encoded string as an environment variable or a command-line argument.
The entry point to the sidecar is the [remotefs tool](cmd/remotefs/README.md) which leverages the [azmount tool](cmd/azmount/README.md).

The encrypted filesystem sidecar uses the SKR library to release key material from Azure Key Vault instances required for mounting the encrypted filesystems required by the application.

The ``examples/encfs`` shows an example of how the encrypted filesystem sidecar can be deployed within a confidential container group on ACI.

## Dependencies

- Golang 1.24 or later
- Docker
- GCC 9.4.0 or later

# Contributing

To take administrator actions such as adding users as contributors, please refer to [engineering hub](https://eng.ms/docs/initiatives/open-source-at-microsoft/github/opensource/repos/jit)

This project welcomes contributions and suggestions.
Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution.
For details, visit <https://cla.microsoft.com>.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment).
Simply follow the instructions provided by the bot.
You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines.
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party’s policies.
