# Kung Pao Chicken
Translates Iptables into Halo Firewall Policies

(WARNING : Halo Firewall Policies will overwrite the current Iptables)

Author: *Hana Lee* - *hlee@cloudpassage.com*

##Requirements and Dependencies
Run bundle install, it should install:
* json
* rest-client
* oauth2
* base64

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

Running `ConvertIPtablesToHaloFirewallPolicies.rb` will input a list of IP addresses, access those servers, retrieve their IPtables, convert the firewall rules, and use the Halo API to create Halo Firewall Policies.



