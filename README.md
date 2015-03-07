##Kung Pao Chicken  
Version: 1.0
Authors: *Hana Lee* - *hlee@cloudpassage.com*, *David Sackmary* - *dsackmary@cloudpassage.com*

###Translates Iptables into Halo Firewall Policies
There are two programs in this repo:  
* The first gets iptables from a list of servers using the command: "iptables -L -n -v".  This program requires an input list of IP addresses, usernames and passwords.  If you have another way to do this, you are welcome to do so.  
* The second program generates Halo Firewall Policies from iptables.

NOTES:  
* This repo does not alter the servers it touches in any way.
* In order to deploy the Halo Firewall Policies generated, please reference http://www.cloudpassage.com/document_images/API_Guide/API_Guide.pdf )
* When a Halo Firewall Policy is deployed, it will overwrite the iptables which is current on that server.

###Requirements and Dependencies
* json
* rest-client
* oauth2
* base64
* glob

###Readme & License:
* **README.md**   The one you're reading now...
* **license.txt**   The cure for insomnia

###Files for Getting Iptables from Servers:
* **get_iptables.py**  RUN THIS ONE ~ will input a list of IP addresses, access those servers, retrieve their Iptables. 
* **server_list.txt**  Sample input file for get_iptables.py  (see usage below)

###Files for Generating Firewall Rules:

* **api.py**   Last stop before the internets.
* **create_policy.py**   Routines called by generate_firewall_rules.
* **generate_firewall_rules.py**   RUN THIS ONE ~ Generate Halo Firewall Rules
* **kpc.py**   Check existing IP zones and create new IP zones, network services and network interfaces. 
* **read_iptables.py**   Read Iptables from current directory

###Installation 

Clone, download, or fork the git repo, then configure as below.

###Configuration

You need to provide three ENV variables for your account, with the user specific api credentials
available to you via the  CloudPassage admin view.

These can be set in various ways, via .bashrc , via inline , etc. 
```
export HALO_KEY_ID = 'xxxxx'
export HALO_SECRET_KEY  = 'xxxxxxxxxxxx'
export HALO_HOST = 'api.cloudpassage.com'
```

###Usage:
```
python get_iptables.py -i server_list.txt 
python generate_firewall_rules.py  
```

Translates existing Iptables into Halo Firewall Policies.  There are two programs in this repo:  
* The first gets iptables from a list of servers using the command: "iptables -L -n -v".  It outputs files in the current directory, one per server, with each file named after the server and containing the iptables for that server.  This program requires an input list of IP addresses, usernames and passwords.  This program is provided as a convenience. If you have another way to do this which you prefer, you are welcome to do so.  
* The second program generates Halo Firewall Policies.  It opens all files in the current directory with an ".iptables" extension, and outputs files with a ".JSON" extension.

###Example:
Assume 'server_list.txt' contains this line:  my_server username pwd
- Running get_iptables.py will outputvthe file 'my_server.iptables'.
- Running generate_firewall_rules.py will read 'my_server.iptables' and install the resulting firewall policy into the Halo account specified in the config.conf file.  If there are iptable rules which cannot be converted, they will be placed into a filed named *** in the current directory
