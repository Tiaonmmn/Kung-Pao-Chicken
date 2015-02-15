#!/usr/bin/env python

# __author__ = 'nick'

# you need paramiko module for this to run
# pip install paramiko

import paramiko, argparse, csv, time
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', action='store', default='./server_list.txt',
                    help='file path & name for server list')
parser.add_argument('--keypair', '-k', action='store', default='/home/f/.ssh/id_rsa',
                    help='Keypair for SSH. WARNING! This will overwrite any keypair name from the input file')
parser.add_argument('--daemon_key', action='store', default='',
                    help='HALO daemon key for registration')
parser.add_argument('--tag', '-t', action='store', default='',
                    help='HALO server group tag for registration')
parser.add_argument('--server_label', '-s', action='store', default='',
                    help='Server label for registration')
parser.add_argument('--debug', '-d', action='store_true', default=True,
                    help='[CoOlNiCk] It will enable debug mode while executing the script')
args = parser.parse_args()

server_list = list(csv.reader(open(args.input, 'rb'), delimiter=' ', skipinitialspace=True))

for server in server_list:
    ip = server[0]
    id = server[1]
    password = server[2]
    if args.keypair == None and len(server) > 3:
        keypair = server[3]
    else:
        keypair = args.keypair
    if args.debug:
        print ('Server IP: %s\nLogin ID: %s\nLogin Password: %s\nKeypair: %s\n' % (ip, id, password, keypair))

    iptables = subprocess.Popen("sudo iptables -L", stdout=subprocess.PIPE, shell=True).stdout.read()
    print iptables





