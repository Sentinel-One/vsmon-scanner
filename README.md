# ``vsmon-scanner``

## General
The scanner reveals instances of Windows remote debugging server (msvsmon.exe) in the network. The scanner is not production-ready yet, unexpected behavior can still occur. Released without any warranty.

## Scanning
The script allows to scan the network in a few ways:
- Broadcast probe to the specified network adapter. Pass --ip_bind IP-of-adapter
- Send probe to the specified IP address. Pass --ip_bind IP-of-adapter --ip_dst IP-dst
- Broadcast probe to all network adapters. Run the script with no paramters.

## Examples

Assuming that the IP address of the network adapter is 192.168.195.1, to broacast the probe to all hosts connected to 192.168.195.1 run:

``vsmon-scanner --ip_bind 192.168.195.1``

To scan the host 192.168.195.168 in 192.168.195.1 network, run:

``vsmon-scanner --ip_bind 192.168.195.1 --dst_ip 192.168.195.168``

## Installation

Run 'pip install -r requirements.txt' to install dependencies.

## Credits
* This open-source project is backed by [SentinelOne](https://www.sentinelone.com/blog/)

See more details about msvsmon.exe in the blog post: 
