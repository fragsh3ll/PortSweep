# PortSweep

PortSweep is a shell script that makes port scanning more efficient. It combines the scan power of masscan, the version accuracy and script scanning of nmap, and the parsing power of xmlstarlet and xsltproc. Masscan will do the initial scan, then xmlstarlet will parse the results and feed it to Nmap. Nmap will do version scanning and default script scan (feel free to modify this) for the discovered ports, and finally xsltproc will convert the output into a nice HTML table.

```
# ./portsweep.sh 
________             _____________                            
___  __ \______________  /__  ___/__      ___________________ 
__  /_/ /  __ \_  ___/  __/____ \__ | /| / /  _ \  _ \__  __ \
_  ____// /_/ /  /   / /_ ____/ /__ |/ |/ //  __/  __/_  /_/ /
/_/     \____//_/    \__/ /____/ ____/|__/ \___/\___/_  .___/ 
                                                     /_/      

[*] Usage: ./portsweep.sh <ports>[all,top-1000,top-100,80,443,445,etc.] <rate> <file>
[*] Example: ./portsweep.sh 21,22,23,80,443 5000 ips.txt
[*] File containing IP addresses can be a single IP or CIDR notated
```

Usage is simple. Just give it some ports, a scan rate, and a file containing a list of IP addresses.

*Setting the ports to `top-100` or `top-1000` will scan for the top 100 or 1000 ports (taken from nmap).*

If at least one open port is discovered, a timestamped folder will be created in the current directory and a number of files will be outputted when the scan finishes:

```
# ls -l
total 48
-rw-r--r-- 1 root root    88 Feb 24 16:25 ip_port.txt
-rw-r--r-- 1 root root    10 Feb 24 16:25 liveips.txt
-rw-r--r-- 1 root root  1520 Feb 24 16:25 masscan_2019-02-24_162510.xml
-rw-r--r-- 1 root root   779 Feb 24 16:26 nmap_2019-02-24_162510.gnmap
-rw-r--r-- 1 root root  3128 Feb 24 16:26 nmap_2019-02-24_162510.nmap
-rw-r--r-- 1 root root 10736 Feb 24 16:26 nmap_2019-02-24_162510.xml
-rw-r--r-- 1 root root 12436 Feb 24 16:26 table_2019-02-24_162510.html
```

* `ip_port.txt` is a list of open ports with their associated IP address in `<IP>:<PORT>` format. 
* `liveips.txt` contains the IP addresses that returned at least one open port.
* `table_<timestamp>.html` is a nicely formatted HTML table containing results from nmap's version scanning, NSE, etc.
* The rest of the files are scan results from nmap and masscan


