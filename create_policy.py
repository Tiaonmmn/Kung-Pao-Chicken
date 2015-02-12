import json 
from read2 import read_Iptables
from get_info import *

mylist_input, mylist_output = read_Iptables()
print "print mylist following read_Iptables()"
print mylist_input
print mylist_output
latest_IP = latest_IP()
latest_Service = latest_Service()
IMP =[]
for k,v in latest_Service:
    if k== "ICMP/0":
        IMP.append(v)
print IMP
latest_Interface = latest_Interface()
def create_Policy(mylist_input,mylist_output,latest_IP, latest_Service, latest_Interface):
    policy ={}
    policy_count = 0 #for naming 
    
    rule = {}
    rule.setdefault('firewall_rules', [])
    store = None
    # dict1 = {'name': name, 'platform': "linux", rule}  
    # dict2 = {'chain': INPUT/OUTPUT, 'active': True, 'firewall_source': source, 'firewall_service': nameOftheService, 'firewall_interface':, 'connection_states': , 'action': ,'log': }
    for line in mylist_input:
        log = False
        IP_id = None
        Service_id = None
        service_name =None
        interface_id = None
        if line[3] == "LOG":
            store = line[8]
            continue
        if line[3] == "ACCEPT" or line[3] == "DROP":
            action = line[3]
            if store == line[8]:
                log = True

        if line[8] == "0.0.0.0/0":
            line[8] = "any"
        for k, v in latest_IP:
            if line[8] == k:
                IP_id = v

        for k, v in latest_Interface:
            if line[6] == k:
                interface_id = v
                
        for i in range(len(line)):
            if (("spt" in line[i]) or ("dpt" in line[i])):
                port = line[i].split(':')[1]
                protocol = line[4].upper()
                service_name = protocol + "/" + port
            elif("icmptype" in line[i]):
                port = line[i+1].strip('\n')
                protocol = line[4].upper()
                service_name = protocol + "/" + port
            elif("multiport" in line[i]):
                port = line[i+2]
                protocol = line[4].upper()
                service_name = protocol + "/" + port
            if "state" in line[i]:
                states = line[i+1].strip('\n')
        for k, v in latest_Service:
            if service_name == k:
                Service_id =v                

        dict2 = {'chain': "INPUT", 'active': True, 'action': action, 'firewall_interface': interface_id, 'firewall_source' : {'id': IP_id, "type":"FirewallZone"},
                 'firewall_service' : Service_id, 'connection_states': states, 'log': log} 
        rule['firewall_rules'].append(dict2)
    
    dict1 = {'firewall_rules':rule['firewall_rules'], 'platform': 'linux', 'name': 'first_creation'}
    policy = {'firewall_policy': dict1}
    return policy
 

policies = create_Policy(mylist_input, mylist_output,latest_IP, latest_Service, latest_Interface)   
print json.dumps(create_Policy(mylist_input,mylist_output,latest_IP, latest_Service, latest_Interface), indent = 4 )

#post_firewallPolicy(create_Policy(mylist_input,mylist_output))