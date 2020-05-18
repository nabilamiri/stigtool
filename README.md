# stigtool
## About
stigtool is designed to be used for meeting the requirements of STIG compliance on networking devices. Today the tool meets only the requirements of Cisco IOS XE Switch L2S Security Technical Implementation Guide DRAFT Version: 1 Release: 0.1 21 Jan 2020. Future releases will contain RTR and NDM functionality.

The tool relies on Nornir as an automation framework: https://nornir.readthedocs.io/en/latest/tutorials/intro/overview.html

## Instructions
/inventory/hosts.yml will need to be updated to contain the hosts that you will run against.

You will need to create a .env file with the follow set or these variables will need to be added to your PATH (where ? is replaced by it's corresponding value):
```
username=?  
password=?  
```
The tool itself can be run as:
```
python l2s.py
```

## Docker
To build the docker version you will need to run:

```
docker build -t stigtool .
docker run stigtool
```
