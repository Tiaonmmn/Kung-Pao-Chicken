import re
import json
import collections
import re
from collections import defaultdict
from api import *

#REPLACE IPTABLES BELOW WITH THIS CODE...
#    text_file = open('LDS_test.txt', 'r')
#    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
#    chain = iptc.Chain(iptc.pyTable(iptc.Table.FILTER), "OUTPUT")
#
# OR ... use Eddie's script to get Iptables.  That way, admins can see what their firewall rules $

def read_Iptables():
    mylist_input =[]
    mylist_output =[]

    text_file = open('iptables_test.txt', 'r')
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
