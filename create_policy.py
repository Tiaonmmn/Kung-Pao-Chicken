import json
from collections import OrderedDict


def create_Policy(filename, mylist_input,mylist_output,latest_IP, latest_Service, latest_Interface):
    policy          = {}    
    rule            = {}
    rule.setdefault('firewall_rules', [])
    store           = None
    exclude_input   = []
    exclude_output  = []
    count_input     = 0
    count_output    = 0
    
    for line in mylist_input:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None
        action          = None
        comment         = None
        skip            = False
       
        
        #check LOG
        if line[3] == "LOG":
            store = line[8]
            count_input = count_input + 1
            continue
        
        
        #define action. if it's not an action then it's one of the special chain.
        #collect the name of special chain and store it in comment
        if ((line[3] == "ACCEPT") or (line[3] == "DROP") or (line[3] == "REJECT")):
            action = line[3]
            if store == line[8]:
                log = True
        elif log == False:
            print "3"
            exclude_input.append(count_input)
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
                    port = port.rstrip('\n')
                    service_name = protocol + "/" + port
                elif("icmptype" in line[i] or "type" in line[i]):
                    port = line[i+1].strip('\n')
                    if port != "0" and port != "8" and port != "13"and port != "17":
                        print "4"
                        exclude_input.append(count_input)
                        skip = True
                    else:    
                        protocol = line[4].upper()
                        service_name = protocol + "/" + port
                        #print service_name
                        #print skip
                elif("multiport" in line[i]):
                    port = line[i+2].rstrip('\n')
                    protocol = line[4].upper()
                    service_name = protocol + "/" + port
                if "state" in line[i]:
                    states = line[i+1].strip('\n')
            for k, v in latest_Service:
                if service_name == k:
                    Service_id =v
        else:
            exclude_input.append(count_input)
            skip = True
        
        count_input = count_input + 1
        #define comment
        for i in range(len(line)):
            if "comment:" in line[i]:
                comment = line[i].split(':')[1]    
        
        if skip == True:
            continue
        
        dict2 = {'chain'                : "INPUT",
                 'active'               : True,
                 'action'               : action,
                 'firewall_interface'   : interface_id,
                 'firewall_source'      : {'id': IP_id, "type":"FirewallZone"},
                 'firewall_service'     : Service_id,
                 'connection_states'    : states,
                 'log'                  : log,
                 'comment'              : comment
                 }
        
        rule['firewall_rules'].append(dict2)
    
    #Out bound firewall rules
    for line in mylist_output:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None
        comment         = None
        skip            = False

        #check LOG
        if line[3] == "LOG":
            store = line[8]
            count_output = count_output + 1
            continue
        
        #define action. if it's not an action then it's one of the special chain.
        #collect the name of special chain and store it in comment
        if line[3] == "ACCEPT" or line[3] == "DROP" or line[3] == "REJECT":
            action = line[3]
            if store == line[8]:
                log = True
        elif log !=False:
            exclude_output.append(count_output)
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
                    port = port.rstrip('\n')
                    protocol = line[4].upper()
                    service_name = protocol + "/" + port
                elif("icmptype" in line[i] or "type" in line[i]):
                        port = line[i+1].strip('\n')
                        if port != "0" and port != "8" and port != "13" and port != "17":
                            exclude_output.append(count_output)
                            skip = True
                        else:    
                            protocol = line[4].upper()
                            service_name = protocol + "/" + port
                elif("multiport" in line[i]):
                    port = line[i+2].rstrip('\n')
                    protocol = line[4].upper()
                    service_name = protocol + "/" + port
                    print service_name
                if "state" in line[i]:
                    states = line[i+1].strip('\n')
            for k, v in latest_Service:
                if service_name == k:
                    print service_name
                    Service_id =v
                    print Service_id
                    
        else:
            exclude_output.append(count_output)
            skip = True
        count_output = count_output + 1
        
        #define comment
        for i in range(len(line)):
            if "comment:" in line[i]:
                comment = line[i].split(':')[1]
            
        if skip == True:
            continue
     
        #print "OUTPUT"
        dict2 = {'chain'                : "OUTPUT",
                 'active'               : True,
                 'action'               : action,
                 'firewall_interface'   : interface_id,
                 'firewall_source'      : {'id': IP_id, "type":"FirewallZone"},
                 'firewall_service'     : Service_id,
                 'connection_states'    : states,
                 'log'                  : log,
                 'comment'              : comment
                 }
        
        rule['firewall_rules'].append(dict2)
    dict1 = {'firewall_rules'   : rule['firewall_rules'],
             'platform'         : 'linux',
             'name'             : filename}
    
    policy = {'firewall_policy': dict1}
    
    exclude_input  = list(OrderedDict.fromkeys(exclude_input))
    exclude_output = list(OrderedDict.fromkeys(exclude_output))
    return policy, exclude_input, exclude_output
