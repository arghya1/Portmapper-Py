# importing nmap in our script
import nmap

# variable to call nmap's portscanner functionality
mapper = nmap.PortScanner()

# Hardcoding Target
target = "localhost"
# Setting using options
options = "-sV -sC scan_results"

# Starting to Scan the Target
mapper.scan(target, arguments=options)


for host in mapper.all_hosts():
    print("Host: %s (%s)" % (host, mapper[host].hostname()))
    print("State: %s" % mapper[host].state())
    for protocol in mapper[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = mapper[host][protocol]
        for port, state in port_info.items():
            print("Port: %s\tState: %s" % (port, state))