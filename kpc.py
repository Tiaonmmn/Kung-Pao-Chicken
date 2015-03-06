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
    #print "EXXXXXXXXX"    

    for line in mylist_input:
        #print line[8]
        if line[8] not in existing_IP.values():
            match = False
            if zone_count == 0:
                match = True
                dict1 ={'name': line[8], 'ip_address':line[8]}
                zone['firewall_zone'].append(dict1)
               #print zone['firewall_zone']    
                zone_count = zone_count + 1
            else:
                for i in range(zone_count):
                    if line[8] == dict1['name']:
                        match = True

            if match == False:
                dict1 ={'name': line[8], 'ip_address':line[8]}
                zone['firewall_zone'].append(dict1)
    
    for line in mylist_output:
        if line[9] not in existing_IP.values():
            match = False
            if zone_count == 0:
                match = True
                dict1 ={'name': line[9], 'ip_address':line[9]}
                zone['firewall_zone'].append(dict1)
                #print zone['firewall_zone']    
                zone_count = zone_count + 1
            else:
                for i in range(zone_count):
                    if line[8] == dict1['name']:
                        match = True

            if match == False:
                dict1 ={'name': line[9], 'ip_address':line[9]}
                zone['firewall_zone'].append(dict1)
             
    return zone

# create network services
# if network service is not in Halo then we will need to create a new one
def create_networkService(mylist_input, mylist_output,existing_Service):
    service =[]
    service_count = 0
    service_create_in_input = []
    print "kpc.py"
    print existing_Service
    for line in mylist_input:
        for i in range(len(line)):
            if (("spt" in line[i]) or ("dpt" in line[i])):
                port = line[i].split(':')[1]
                protocol = line[4].upper()
                port = port.rstrip('\n')
                if (port, protocol) not in existing_Service:
                    print port, protocol
                    match = False
                    if service_count == 0:
                        match = True
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service.append(dict1)
                        service_create_in_input.append((port,protocol))
                        service_count = service_count + 1
                    else:
                        for i in range(service_count):
                            if (protocol +"/" + port) == dict1['name']:
                                match = True
                                
                    if match == False:
                        dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                        service_create_in_input.append((port,protocol))

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
                        service_create_in_input.append((port, protocol))
                        service_count = service_count + 1
                    else:
                        for i in range(service_count):
                            if (protocol +"/" + port) == dict1['name']:
                                match = True
                                    
                    if match == False:
                            dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                            service.append(dict1)
                            service_create_in_input.append((port, protocol))
                            
    for line in mylist_output:
            for i in range(len(line)):
                if (("spt" in line[i]) or ("dpt" in line[i])):
                    port = line[i].split(':')[1]
                    port = port.rstrip('\n')
                    protocol = line[4].upper()
                    if (((port, protocol) not in existing_Service) and ((port,protocol) not in service_create_in_input)):
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
                                
                elif ("multiport" in line[i]):
                    port = line[i+2]
                    protocol = line[4].upper()
                    if (((port, protocol) not in existing_Service) and ((port,protocol) not in service_create_in_input)):
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
    #print service        
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
        #print "********"
        #print line
        
        if len(line) < 2:
            continue
        elif (line[7] != "*") and (line[7] not in existing_Interfaces):
            dict1 = {'name': line[7]}
            interface['firewall_interface'].append(dict1)
    return interface
