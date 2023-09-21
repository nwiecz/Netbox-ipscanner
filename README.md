# Netbox-ipscanner
Dynamic IP Scanner script for NetBox to programatically populate NetBox's IPAM

## Requirements
This script requires the `nmap` system package and Python library to run

## Installation
```bash
netbox_path=/opt/netbox

# Install system packages (tweak for you package manager)
apt-get update
apt-get install nmap

# Install Python library
pip install python-nmap

# Download custom script
curl 'https://raw.githubusercontent.com/Scraps23/Netbox-ipscanner/master/netbox_ipscanner.py' \
    -o "${netbox_path}/netbox/scripts/netbox_ipscanner.py"
```

## What it does

1. This script will either: 
   - Consume a NetBox Prefix object if a `target_prefix` was provided
   - Pull all NetBox Prefix objects otherwise
2. It will then perform `nmap.PostScannerYield.scan()` against that prefix with the `-sL` NMAP options
3. Based on the returned data and form data, the script will:
   - Mark the address deprecated, if there was no response and the address was not already Deprecated or Reserved
   - Mark the address active, if there was a resposne and the address was Deprecated
   - Create a new address with the returned `hostname`, if there was already none and `create_new` is checked
   - Skip the address, if it didn't match the filters or other criteria
