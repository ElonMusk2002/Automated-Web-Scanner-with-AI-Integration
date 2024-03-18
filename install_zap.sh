#!/bin/bash

# Navigate to the Downloads directory
cd ~/Downloads

# Download the ZAP installation script
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh

# Run the ZAP installation script with sudo privileges
sudo bash ZAP_2_14_0_unix.sh