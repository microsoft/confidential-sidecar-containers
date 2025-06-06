#!/bin/bash

set -e

latest=$(gh release list -R microsoft/confidential-aci-testing -L 1 --json tagName --jq '.[0].tagName')
gh release download $latest -R microsoft/confidential-aci-testing
pip install c_aci_testing*.tar.gz
rm c_aci_testing*.tar.gz