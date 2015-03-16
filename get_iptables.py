### Get_iptables.py 
### INPUT: 'server_list.txt' from the same directory,
###         unless a different file is supplied as an arg.  
###         Each line in server_list.txt should contain 3 values:  
###         ip_address user pwd
### OUTPUT: A set of files in the same directory.
###         Each is named by the ip_address of its' corresponding line.
###       
### Note: More error checking should be done for bad/down servers.

import paramiko, argparse, csv, time, os, socket

def get_Iptables(host, id, pwd):
    trans = paramiko.Transport((host, 22))
    host_key = os.path.expanduser('~/Documents/hlee.pem')    
    trans.connect(username=id, password= host_key)
    session = trans.open_channel("session")
    session.exec_command('sudo iptables -L -v -n')
    session.recv_exit_status()
    while not session.recv_ready():
        time.sleep(30)
    return session.recv(32768) #max buffersize supported by paramiko

def get_IptableSave(host, id, password):
    trans = paramiko.Transport((host, 22))
    trans.connect(username=id, password=password)
    session = trans.open_channel("session")
    session.exec_command('sudo iptables-save')
    session.recv_exit_status()
    while not session.recv_ready():
        time.sleep(30)
    return session.recv(32768) #max buffersize supported by paramiko

### Begin Execution ###
parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', action='store', default='./server_list.txt',
                    help='File path & name for server list')
args = parser.parse_args()
args.debug = False
server_list = list(csv.reader(open(args.input, 'rb'), delimiter=' ', skipinitialspace=True))
for server in server_list:
    host = server[0]
    id = server[1]
    password = server[2]

    iptables = get_Iptables(host, id, password)
    outfile = host + ".iptables"
    
    iptables_save = get_IptableSave(host, id, password)
    outfile_save = host + ".saves"
    
    iptable_file = open(outfile,"w")
    iptable_file.write(iptables)    
    
    iptable_save_file = open(outfile_save, "w")
    iptable_save_file.write(iptables_save)

    iptable_file.close()
    iptable_save_file.close()
