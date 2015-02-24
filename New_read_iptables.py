import re
import json
import collections
import re
#def read_Iptables()

#    text_file = open('LDS_test.txt', 'r')
#    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
#    chain = iptc.Chain(iptc.pyTable(iptc.Table.FILTER), "OUTPUT")


def read_Iptables():
    mylist_input =[]
    mylist_output =[]
    chain = []
    text_file = open('hana1.txt', 'r')

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
                chain.append(tokens[1])
                flag = ''
        elif tokens[1] == "pkts":
            continue
        elif tokens[3] != None:
            if flag == 'i':
                mylist_input.append(tokens)             
            elif flag == 'f':
                continue
            elif flag == 'o':
                mylist_output.append(tokens)             
        if flag == 'x':
            print "flag=x.  something's wrong"
    return mylist_input, mylist_output,chain


def Find_special_chain(chain):
    
    text_file = open('hana1.txt', 'r')
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
    count = 0
    print mylist_input
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
    
    print json.dumps(token_hash, indent = 2)
    for i in range(len(mylist_input)):
        
        if mylist_input[i][3] != "ACCEPT" or mylist_input[i][3] != "REJECT" or mylist_input[i][3] != "LOG" or mylist_input[i][3] != "DROP":
            mylist_input_final.append(mylist_input[i])
            for value in token_hash[mylist_input[i][3]]:
                if len(value) < 2:
                    continue
                else:
                    mylist_input_final.append(value)
        else:
            mylist_input_final.append(mylist_input[i])
            
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
            
    #    for key in token_hash.keys():
    #        print "+++++++"
    #        print key
    #        print mylist_input[i][3]
    #        print "+++++++"
    #        if key == mylist_input[i][3]:
    #            for value in token_hash[key]:
    #                if len(value) < 2:
    #                    continue
    #                else:
    #                    mylist_input_final.append(value)
    #                    print value
    #        else:
    #            mylist_input_final.append(mylist_input[i])
    #            print "!!!"
    #            print mylist_input[i]
    #
    #for i in range(len(mylist_output)):
    #    for key in token_hash.keys():
    #        if mylist_output[i][3] == key:
    #            for value in token_hash[key]:
    #                if len(value) < 2:
    #                    continue
    #                else:
    #                    mylist_output_final.append(value)
    #        else:
    #            mylist_output_final.append(mylist_output[i])

        
    
    return mylist_output_final, mylist_input_final
    



mylist_input, mylist_output,chain = read_Iptables()

shash = Find_special_chain(chain)
mylist_output_final, mylist_input_final= merge_special_chain(mylist_input, mylist_output,shash)

print mylist_input_final
print "___________________"
print mylist_output_final