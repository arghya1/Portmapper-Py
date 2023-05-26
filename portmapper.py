# importing nmap in our script
import nmap

# variable to call nmap's portscanner functionality
mapper = nmap.PortScanner()

# Hardcoding Target > Try nmap ip: 45.33.49.119 use ping nmap.org to check
target = "45.33.49.119"
# Setting using options
#options = "-sV -sC scan_results"
options = "-sV"
# Starting to Scan the Target
print("Here we go...")
mapper.scan(target, arguments=options)

# Prints / Shows Host, State, Protocol, and Open ports

for host in mapper.all_hosts():
    print("Starting to scan Host.")
    print("Host: %s (%s)" % (host, mapper[host].hostname()))
    print("Looking for state.")
    print("State: %s" % mapper[host].state())
    for protocol in mapper[host].all_protocols():
        print("What is the protocol?")
        print("Protocol: %s" % protocol)
        print("Getting port info")
        port_info = mapper[host][protocol]
        for port, state in port_info.items():
            print("Here is the port bruh.")
            print("Port: %s\tState: %s" % (port, state))