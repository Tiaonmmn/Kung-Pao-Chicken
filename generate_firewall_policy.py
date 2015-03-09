import json
import glob

from read_iptables import read_IptableSave,read_Iptables, Find_special_chain, merge_special_chain
from api import get_IPzones, get_Services, get_interfaces
from kpc import existing_IPzone, existing_service, existing_interfaces
from kpc import create_IPzone, create_networkService, create_networkInterface
from api import latest_IP, latest_Service, latest_Interface, post_Services, post_IPzones, post_Services, post_Interfaces, post_firewallPolicy
from create_policy1 import create_Policy
from exclude_report import exclude_result

exclude_file = open("exclude.txt", "w")
# Get Iptables
files = zip((glob.glob("*.iptables")), (glob.glob("*.saves")))
print files
for n, s in files:
    print "START " + n
    save_input, save_output,save_forward = read_IptableSave(s)
    mylist_input, mylist_output,chain, exclude_forward = read_Iptables(n)
    shash = Find_special_chain(n, chain)
    if not shash:
        mylist_input_final = mylist_input
        mylist_output_final = mylist_output
    else:		    
        mylist_output_final, mylist_input_final= merge_special_chain(mylist_input, mylist_output,shash)

    existing_IP = existing_IPzone(get_IPzones())
    existing_Service = existing_service(get_Services())
    existing_Interfaces = existing_interfaces(get_interfaces())

    zones = create_IPzone(mylist_input_final, mylist_output_final, existing_IP)
    services = create_networkService(mylist_input_final,mylist_output_final,existing_Service)
    interfaces = create_networkInterface(mylist_input_final,mylist_output_final,existing_Interfaces)
    
    post_IPzones(zones)
    post_Interfaces(interfaces)
    post_Services(services)
    
    Service_latest = latest_Service()
    IP_latest = latest_IP()
    Interface_latest = latest_Interface()
    
    policies, exclude_input, exclude_output = create_Policy(n, mylist_input_final, mylist_output_final, IP_latest, Service_latest, Interface_latest)
    
    exclude_result(n, save_input, save_output, save_forward, exclude_input, exclude_output, exclude_file)
    post_firewallPolicy(policies)

exclude_file.close()