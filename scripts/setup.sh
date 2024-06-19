#!/bin/bash

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y cryptsetup
./scripts/install-c-aci-testing.sh
python -m pip install -r requirements.txt