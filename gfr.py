import json

from read_Iptables import read_Iptables
from api import get_IPzones, get_Services, get_interfaces
from api import latest_IP, latest_Service, latest_Interface, post_Services
from kpc import create_IPzone, create_networkService, create_networkInterface
from kpc import existing_IPzone, existing_service, existing_interfaces
from create_policy import create_Policy

# Get Iptables
mylist_input, mylist_output = read_Iptables()

existing_IP = existing_IPzone(get_IPzones())
existing_Service = existing_service(get_Services())
existing_Interfaces = existing_interfaces(get_interfaces())
print existing_Service
print"++++++++++++++++++++++++++++++++++++"

latest_IP = latest_IP()
latest_Service = latest_Service()
latest_Interface = latest_Interface()

#from get_info
print latest_Service
print latest_IP
print "+++++++++++++++"
for k,v in latest_IP:
    print k + "and" + v

policies = create_Policy(mylist_input, mylist_output, latest_IP, latest_Service, latest_Interface)
print json.dumps(policies, indent = 4 )

zones = create_IPzone(mylist_input, mylist_output, existing_IP)
services = create_networkService(mylist_input,mylist_output,existing_Service)
interfaces = create_networkInterface(mylist_input,mylist_output,existing_Interfaces)
post_Services(services)
