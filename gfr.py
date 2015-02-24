import json

from New_read_iptables import *
from api import get_IPzones, get_Services, get_interfaces
from api import latest_IP, latest_Service, latest_Interface, post_Services, post_IPzones, post_Services, post_Interfaces, post_firewallPolicy
from kpc import create_IPzone, create_networkService, create_networkInterface
from kpc import existing_IPzone, existing_service, existing_interfaces
from create_policy import create_Policy

# Get Iptables
mylist_input_final, mylist_output_final 

existing_IP = existing_IPzone(get_IPzones())
existing_Service = existing_service(get_Services())
existing_Interfaces = existing_interfaces(get_interfaces())


latest_IP = latest_IP()
latest_Service = latest_Service()
latest_Interface = latest_Interface()


zones = create_IPzone(mylist_input_final, mylist_output_final, existing_IP)
services = create_networkService(mylist_input_final,mylist_output_final,existing_Service)
interfaces = create_networkInterface(mylist_input_final,mylist_output_final,existing_Interfaces)
policies = create_Policy(mylist_input_final, mylist_output_final, latest_IP, latest_Service, latest_Interface)
print "gfy.py"
print json.dumps(policies, indent = 4 )

post_IPzones(zones)
post_Interfaces(interfaces)
post_Services(services)

post_firewallPolicy(policies)