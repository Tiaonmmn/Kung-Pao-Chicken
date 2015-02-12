import re
import json
import collections
import re
from collections import defaultdict
from api import * 
#def read_Iptables()

#    text_file = open('LDS_test.txt', 'r')
#    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
#    chain = iptc.Chain(iptc.pyTable(iptc.Table.FILTER), "OUTPUT")

def read_Iptables():
    mylist_input =[]
    mylist_output =[]

    text_file = open('LDS_test.txt', 'r')
    for line in text_file:
        tokens = re.split(r"[' ']+", line)

        if len(tokens) < 2:
            continue
        elif tokens[0] == "Chain":
            if tokens[1] == "INPUT":
                flag = 'i'
            elif tokens[1] == "FORWARD":
                flag = 'f'
            elif tokens[1] == "OUTPUT":
                flag = 'o'
            else:  
                print "wut?"
        elif tokens[1] == "pkts":
            continue
        elif tokens[3] == "ACCEPT":
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
                continue
            elif flag == 'o':
                mylist_output.append(tokens)             
        elif tokens[3] == "REJECT":
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
               continue
            elif flag == 'o':
                mylist_output.append(tokens)             
        elif tokens[3] == "DROP":
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
               continue
            elif flag == 'o':
                mylist_output.append(tokens)
        elif tokens[3] == "LOG":
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
               continue
            elif flag == 'o':
                mylist_output.append(tokens)                
        else:
            continue
        if flag == 'x':
            print "flag=x.  something's wrong"
    return mylist_input, mylist_output 


# Create dictionary for existing ipzones
def existing_IPzone(jsondata):
    existing_IP ={}
    for entry in jsondata['firewall_zones']:
        existing_IP[entry['name']] = entry['ip_address']
    return existing_IP
    
# Create dictionary for existing firewall services   
def existing_service(jsondata):
    existing_Service = []
    for entry in jsondata['firewall_services']:
        existing_Service.append((entry['port'], entry['protocol']))
    return existing_Service

# Create dictionary for existing firewall interfaces 
def existing_interfaces(jsondata):
    existing_Interface = [] 
    for entry in jsondata['firewall_interfaces']:
        existing_Interface.append(entry['name'])
    return existing_Interface
    
# create_IPzone. 
# we will need to check if the IPzone is in Halo already. If not we will need to create a new IPzone. 
# Tricky part is how do we name the IPzone 
def create_IPzone(mylist_input, mylist_output, existing_IP):
    zone = {}
    zone.setdefault('firewall_zone', [])
    zone_count = 0
    for line in mylist_input:
        if line[8] not in existing_IP.values():
            match = False
            if zone_count == 0:
                match = True
                dict1 ={'name': line[8], 'ip_address':line[8]}
                zone['firewall_zone'].append(dict1)
#                print zone['firewall_zone']    
                zone_count = zone_count + 1
            else:
                for i in range(zone_count):
                    if line[8] == dict1['name']:
                        match = True

            if match == False:
                dict1 ={'name': line[8], 'ip_address':line[8]}
                zone['firewall_zone'].append(dict1)
             
    return zone

# create network services
# if network service is not in Halo then we will need to create a new one
def create_networkService(mylist_input, mylist_output,existing_Service):
    service =[]
    service_count = 0
    
    for line in mylist_input:
        for i in range(len(line)):
            if (("spt" in line[i]) or ("dpt" in line[i])):
                port = line[i].split(':')[1]
                protocol = line[4].upper()
                if (port, protocol) not in existing_Service:
                    match = False
                    if service_count == 0:
                        match = True
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service.append(dict1)
                        service_count = service_count + 1
                    else:
                        for i in range(service_count):
                            if (protocol +"/" + port) == dict1['name']:
                                match = True
                                
                    if match == False:
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service.append(dict1)
            
            elif ("icmptype" in line[i]):
                port = line[i+1].strip('\n')
                protocol = line[4].upper()
                if port == "0":
                   port = None
                if (port, protocol) not in existing_Service:
                    match = False
                    print port, protocol
                    if service_count == 0:
                        match = True
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service.append(dict1)
                        service_count = service_count + 1
                    else:
                        for i in range(service_count):
                            if (protocol +"/" + port) == dict1['name']:
                                match = True
                                    
                    if match == False:
                            dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                            service.append(dict1)
                            
            elif ("multiport" in line[i]):
                port = line[i+2]
                protocol = line[4].upper()
                if (port, protocol) not in existing_Service:
                    match = False
                    if service_count == 0:
                        match = True
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service.append(dict1)
                        service_count = service_count + 1
                    else:
                        for i in range(service_count):
                            if (protocol +"/" + port) == dict1['name']:
                                match = True
                                    
                    if match == False:
                            dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                            service.append(dict1)
            
    return service

# create network interfaces 
# if network interface is not in Halo then we will need to create a new one.
def create_networkInterface(mylist_input,mylist_output,existing_Interfaces):
    interface = {}
    interface.setdefault('firewall_interface', [])
    for line in mylist_input:
        if (line[6] != "*") and (line[6] not in existing_Interfaces):
            dict1 = {'name': line[6]}
            interface['firewall_interface'].append(dict1)
    for line in mylist_output:
        if (line[7] != "*") and (line[7] not in existing_Interfaces):
            dict1 = {'name': line[7]}
            interface['firewall_interface'].append(dict1)
    return interface

#### Main #####

mylist_input, mylist_output = read_Iptables()
existing_IP = existing_IPzone(get_IPzones())
existing_Service = existing_service(get_Services())
existing_Interfaces = existing_interfaces(get_interfaces())
print existing_Service
print"++++++++++++++++++++++++++++++++++++"
zones = create_IPzone(mylist_input, mylist_output, existing_IP)
services = create_networkService(mylist_input,mylist_output,existing_Service)
interfaces = create_networkInterface(mylist_input,mylist_output,existing_Interfaces)
print services

#ofile = open("log.json",'w')
#ofile.write(json.dumps(listrule, indent =2 ))
#print ofile
#ofile.close()
