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
    special_input =[]
    special_output = []
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
            if flag == 'i':
                print "Here"
                special_input.append(tokens[3])
            elif flag == 'f':
                continue
            elif flag == 'o':
                special_output.append(tokens[3])
        if flag == 'x':
            print "flag=x.  something's wrong"
    return mylist_input, mylist_output, special_input, special_output,chain


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

def merge_special_chain(mylist_input, mylist_output, special_input, special_output,shash):

    print special_input
    flag = False
    mylist_input_final = mylist_input
    mylist_output_final = mylist_output
    
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            for key in shash.keys():
                if len(tokens) < 2:
                    continue
                elif tokens[3] == key:
                    shash[entry].extend(shash[tokens[3]])

    
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            for key in shash.keys():
                if entry in special_output:
                    if len(tokens) < 2:
                        continue
                    elif tokens[3] == key:
                        continue
                    else:
                        if tokens in mylist_output_final:
                            continue
                        else:
                            mylist_output_final.append(tokens)
                if entry in special_input:
                    if len(tokens) < 2:
                        continue
                    elif tokens[3] == key:
                        continue
                    else:
                        if tokens in mylist_input_final:
                            continue
                        else:
                            mylist_input_final.append(tokens)
    
                    
    return mylist_output_final, mylist_input_final
    



mylist_input, mylist_output, special_input, special_output, chain = read_Iptables()
shash = Find_special_chain(chain)
mylist_output_final, mylist_input_final = merge_special_chain(mylist_input, mylist_output, special_input, special_output,shash)

print mylist_input_final