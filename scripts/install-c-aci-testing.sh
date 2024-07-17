#!/bin/bash

set -e

gh release download 1.0.2 -R microsoft/confidential-aci-testing
python -m pip install c_aci_testing*.tar.gz
rm c_aci_testing*.tar.gz