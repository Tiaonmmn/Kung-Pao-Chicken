# Generate Firewall Rules
Translates existing Iptables into Halo Firewall Policies

(WARNING : Halo Firewall Policies will overwrite the current Iptables)

Authors: *Hana Lee* - *hlee@cloudpassage.com*
         
##Requirements and Dependencies
* json
* rest-client
* oauth2
* base64
* glob

###Files:
* **README.md**   The one you're reading now...
* **api.py**   All the api calls KPC needs.
* **create_policy.py**   Create firewall policy.
* **generate_firewall_rules.py**   RUN THIS ONE ~ GENERATE FIREWALL RULES.
* **kpc.py**   Check existing and create new IP zones, network services and network interfaces. 
* **read_iptables.py**   Read Iptables from current directory
* **get_iptables.py**  Get all existing Iptables via command lines
* **license.txt**   The cure for insomnia

###Usage:


>gfr.py -s serverlist (or something like that....)

##Installation 

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

Launch locally as :

`./ConvertIPtablesToHaloFirewallPolicies.rb`


##Usage

Running Generate Firewall Rules, aka rgf.py, will input an IPtable, convert the firewall rules, and use the Halo API to create Halo Firewall Policies.

coming soon:
Running Kung Pao Chicken, aka rgf.py, will input a list of IP addresses, access those servers, retrieve their IPtables, convert the firewall rules, and use the Halo API to create Halo Firewall Policies.
