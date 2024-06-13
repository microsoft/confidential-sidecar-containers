#!/bin/bash

sudo apt-get update -y
sudo apt-get install -y cryptsetup
./scripts/install-c-aci-testing.sh
python -m pip install -r requirements.txt