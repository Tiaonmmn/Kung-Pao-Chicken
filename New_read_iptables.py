import re
import json
import collections
import re
import glob
#read the text file and generate input, output and chain for special cases 
def read_Iptables(filename):
    mylist_input =[]
    mylist_output =[]
    chain = []
    exclude_forward = []
    text_file = open(filename, 'r')

    for line in text_file:
        tokens = re.split(r"[' ']+", line)
        print tokens        
        if len(tokens) < 2:
            continue
        elif tokens[0] == "Chain":
            if tokens[1] == "INPUT":
                flag = 'i'
            elif tokens[1] == "FORWARD":
                flag = 'f'
                exclude_forward.append(line)
            elif tokens[1] == "OUTPUT":
                flag = 'o'
            else:
                chain.append(tokens[1])
                flag = ''
        elif tokens[1] == "pkts":
            continue
        elif tokens[3] != None:
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
                exclude_forward.append(line)
                continue
            elif flag == 'o':
                mylist_output.append(tokens)             
        if flag == 'x':
            print "flag=x.  something's wrong"
    return mylist_input, mylist_output,chain, exclude_forward

#finding the speical chain and collect all the firewall rules they have 
def Find_special_chain(filename, chain):
    
    text_file = open(filename, 'r')
    printing = False
    chain_list = []
    name = None
    shash = {}

    for line in text_file:
        m = re.search(r"Chain (\w+)", line)

        if m:
            if m.groups(1)[0] in chain:
                name = m.groups(1)[0]
                printing = True
            else:
                printing = False
        if printing:
            if (("Chain" in line) or ("pkts" in line)):
                pass
            else:
                chain_list.append((name,line))
    
    for i in range(len(chain)):        
        for k, v in chain_list:
            if k == chain[i]:
                shash.setdefault(k,[]).append(v)


    return shash

def merge_special_chain(mylist_input, mylist_output,shash):

    flag = False
    mylist_input_final = []
    mylist_output_final = []
    token_hash = {}
    
    
    # this is for special cases. for nested firewall chain
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            for key in shash.keys():
                if len(tokens) < 2:
                    continue
                elif tokens[3] == key:
                    shash[entry].extend(shash[tokens[3]])

    # tokenize each value in shash 
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            print tokens
            token_hash.setdefault(entry,[]).append(tokens)            
    
    #append spcial chain to mylist_input in order
    for i in range(len(mylist_input)):        
        if mylist_input[i][3] != "ACCEPT" or mylist_input[i][3] != "REJECT" or mylist_input[i][3] != "LOG" or mylist_input[i][3] != "DROP":
            mylist_input_final.append(mylist_input[i])
            print mylist_input[i]
            for value in token_hash[mylist_input[i][3]]:
                if len(value) < 2:
                    continue
                else:
                    mylist_input_final.append(value)
        else:
            mylist_input_final.append(mylist_input[i])
            
    #append special chain to mylist_output in order        
    for i in range(len(mylist_output)):
        if mylist_output[i][3] != "ACCEPT" or mylist_output[i][3] != "REJECT" or mylist_output[i][3] != "LOG" or mylist_output[i][3] != "DROP":
            mylist_output_final.append(mylist_output[i])
            for value in token_hash[mylist_output[i][3]]:
                if len(value) < 2:
                    continue
                else:
                    mylist_output_final.append(value)
        else:
            mylist_output_final.append(mylist_output[i])            
        
    
    return mylist_output_final, mylist_input_final
    


#mylist_input, mylist_output, chain, exclude_forward = read_Iptables(gfr.files[n])

#files = []
#files = glob.glob("*.txt")
#for n in range(len(files)):
#    if files[n] != "server_list.txt":
#        mylist_input, mylist_output,chain, exclude_forward = read_Iptables(files[n])
#        shash = Find_special_chain(files[n], chain)
#        if not shash:
#            continue
#        else:		    
#            mylist_output_final, mylist_input_final= merge_special_chain(mylist_input, mylist_output,shash)
