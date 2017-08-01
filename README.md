# SSHpray
Script to automate task of trying a looted private key across hosts and optionally running a command


./SSHpray.py -h
usage: SSHpray.py [-h] [-i 127.0.0.1] [-k <keyfile>] [-t <targetfile>]
                  [-u <username>] [-v]

optional arguments:

  -h, --help            show this help message and exit
  
  -i 127.0.0.1, --ipaddress 127.0.0.1
                        single ip to test
                        
  -k <keyfile>, --keyfile <keyfile>
                        private key that you have looted
                        
  -t <targetfile>, --targets <targetfile>
                        list of ssh servers in a file, one per line
                        
  -u <username>, --username <username>
                        username associated with key, default is current local
                        user
                        
  -v, --verbose         Optionally enable verbosity
