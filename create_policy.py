def create_Policy(mylist_input,mylist_output,latest_IP, latest_Service, latest_Interface):
    policy          = {}    
    rule            = {}
    rule.setdefault('firewall_rules', [])
    store           = None
    comment         = None
    exclude_input   = []
    exclude_output  = []
    # dict1 = {'name': name, 'platform': "linux", rule}  
    # dict2 = {'chain': INPUT/OUTPUT, 'active': True, 'firewall_source': source, 'firewall_service': nameOftheService, 'firewall_interface':, 'connection_states': , 'action': ,'log': }
    
    
    for line in mylist_input:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None
        action          = None
        
        skip            = False
        
        #check LOG
        if line[3] == "LOG":
            store = line[8]
            continue
        
        
        #define action. if it's not an action then it's one of the special chain.
        #collect the name of special chain and store it in comment
        if ((line[3] == "ACCEPT") or (line[3] == "DROP") or (line[3] == "REJECT")):
            action = line[3]
            if store == line[8]:
                log = True
        else:   
            comment = line[3]
            exclude_input.append(line)
            skip = True
        
        #define source
        if line[8] == "0.0.0.0/0":
            line[8] = "any"
        for k, v in latest_IP:
            if line[8] == k:
                IP_id = v
                
        #define interface
        for k, v in latest_Interface:
            if line[6] == k:
                interface_id = v
        
        #define service. Halo can only process tcp, udp and icmp.
        #For icmp, Halo only supports type 0, 8, 13, 17
        if line[4] == "tcp" or line[4] == "udp" or line[4]== "icmp" or line[4]== "all":      
            for i in range(len(line)):
                if (("spt" in line[i]) or ("dpt" in line[i])):
                    port = line[i].split(':')[1]
                    protocol = line[4].upper()
                    service_name = protocol + "/" + port
                elif("icmptype" in line[i] or "type" in line[i]):
                    port = line[i+1].strip('\n')
                    if port != "0" or port != "8" or port != "13" or port != "17":
                        exclude_input.append(line)
                        skip = True
                    else:    
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
        else:
            skip = True
        
        if skip == True:
            continue
        
        dict2 = {'chain': "INPUT", 'active': True, 'action': action, 'firewall_interface': interface_id, 'firewall_source' : {'id': IP_id, "type":"FirewallZone"},
                 'firewall_service' : Service_id, 'connection_states': states, 'log': log, 'comment': comment}
        rule['firewall_rules'].append(dict2)
        
    for line in mylist_output:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None

        skip            = False
        
        #check LOG
        if line[3] == "LOG":
            store = line[8]
            continue
        
        #define action. if it's not an action then it's one of the special chain.
        #collect the name of special chain and store it in comment
        if line[3] == "ACCEPT" or line[3] == "DROP" or line[3] == "REJECT":
            action = line[3]
            if store == line[8]:
                log = True
        else:
            comment = line[3]
            exclude_output.append(line)
            skip = True
            
       # define destination 
        if line[9] == "0.0.0.0/0":
            line[9] = "any"
        for k, v in latest_IP:
            if line[9] == k:
                IP_id = v
                
        # define interface
        for k, v in latest_Interface:
            if line[7] == k:
                interface_id = v
        
        #define service. Halo can only process tcp, udp and icmp.
        #For icmp, Halo only supports type 0, 8, 13, 17       
        if line[4] == "tcp" or line[4] == "udp" or line[4]== "icmp" or line[4]== "all":             
            for i in range(len(line)):
                if (("spt" in line[i]) or ("dpt" in line[i])):
                    port = line[i].split(':')[1]
                    protocol = line[4].upper()
                    service_name = protocol + "/" + port
                elif("icmptype" in line[i] or "type" in line[i]):
                        port = line[i+1].strip('\n')
                        if port != "0" or port != "8" or port != "13" or port != "17":
                            exclude_output.append(line)
                            skip = True
                        else:    
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
        else:
            skip = True
            
        if skip == True:
            continue
     
        
        dict2 = {'chain': "OUTPUT", 'active': True, 'action': action, 'firewall_interface': interface_id, 'firewall_source' : {'id': IP_id, "type":"FirewallZone"},
                 'firewall_service' : Service_id, 'connection_states': states, 'log': log, 'comment': comment}
        rule['firewall_rules'].append(dict2)
        
    dict1 = {'firewall_rules':rule['firewall_rules'], 'platform': 'linux', 'name': 'first_creation'}
    policy = {'firewall_policy': dict1}
    return policy, exclude_input, exclude_output
