import json
import glob

from New_read_iptables import read_Iptables, Find_special_chain, merge_special_chain
from api import get_IPzones, get_Services, get_interfaces
from api import latest_IP, latest_Service, latest_Interface, post_Services, post_IPzones, post_Services, post_Interfaces, post_firewallPolicy
from kpc import create_IPzone, create_networkService, create_networkInterface
from kpc import existing_IPzone, existing_service, existing_interfaces
from create_policy import create_Policy

# Get Iptables
files = []
files = glob.glob("*.txt")
for n in range(len(files)):
    if files[n] != "server_list.txt":
        mylist_input, mylist_output,chain, exclude_forward = read_Iptables(files[n])
        shash = Find_special_chain(files[n], chain)
        if not shash:
            mylist_input_final = mylist_input
            mylist_output_final = mylist_output
        else:		    
            mylist_output_final, mylist_input_final= merge_special_chain(mylist_input, mylist_output,shash)

        existing_IP = existing_IPzone(get_IPzones())
        existing_Service = existing_service(get_Services())
        existing_Interfaces = existing_interfaces(get_interfaces())


        latest_IP = latest_IP()
        latest_Service = latest_Service()
        latest_Interface = latest_Interface()


        zones = create_IPzone(mylist_input_final, mylist_output_final, existing_IP)
        services = create_networkService(mylist_input_final,mylist_output_final,existing_Service)
        interfaces = create_networkInterface(mylist_input_final,mylist_output_final,existing_Interfaces)
        policies = create_Policy(files[n], mylist_input_final, mylist_output_final, latest_IP, latest_Service, latest_Interface)

        post_IPzones(zones)
        post_Interfaces(interfaces)
        post_Services(services)

        post_firewallPolicy(policies)