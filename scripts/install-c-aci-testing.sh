#!/bin/bash

set -e

latest=$(gh release list -R microsoft/confidential-aci-testing -L 1 --json tagName --jq '.[0].tagName')
gh release download $latest -R microsoft/confidential-aci-testing
python -m pip install c-aci-testing*.tar.gz
rm c-aci-testing*.tar.gz