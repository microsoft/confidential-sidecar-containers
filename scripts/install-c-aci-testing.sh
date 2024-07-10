#!/bin/bash

set -e

gh release download 0.1.20 -R microsoft/confidential-aci-testing
python -m pip install c-aci-testing*.tar.gz
rm c-aci-testing*.tar.gz