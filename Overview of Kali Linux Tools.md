# <p align="left"> 01 Information Gathering </p>
## **DNS Analysis**
- **dnsrecon**
<p> DNSRecon is a Python script that provides the ability to perform:
If a DNS Server Cached records for A, AAAA and CNAME,it check all NS Records for Zone Transfers,enumerates General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT),performs common SRV Record enumeration,Checks for Wildcard Resolution,,it performs a PTR Record lookup for a given IP Range or CIDR and records provided a list of host records in a text file to check.</p>

- **dnsenum**
<p> Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

<p>Get the host’s addresses (A record)</p>
<p>Get the namservers (threaded).</p>
<p>Get the MX record (threaded).</p>
<p>Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).</p>
<p>Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).</p>

- **fierce**
<p>Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It’s really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for. This does not perform exploitation and does not scan the whole internet indiscriminately. It is meant specifically to locate likely targets both inside and outside a corporate network.</p>

## **IDS/IPS Identification**

- **lbd**
<p>Load balancing(lbd) is the technique used in different services for balancing the load across different servers or NICs. It can be in any form. Load balancing can be done to evenly distribute workload through a series of Computer clusters.</p>

- **Wafw00f**
<p>Identifies and fingerprints Web Application Firewall (WAF) products using the following logic:

<p>Sends a normal HTTP request and analyses the response; this identifies a number of WAF solutions.</p>
<p>If that is not successful, it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is.</p>
<p>If that is also not successful, it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to the attacks.</p>

## **Live Host Identification**
- **fping**
-<p>ping is a ping like program which uses the Internet Control Message Protocol (ICMP) echo request to determine if a target host is responding. fping differs from ping in that you can specify any number of targets on the command line, or specify a file containing the lists of targets to ping. Instead of sending to one target until it times out or replies, fping will send out a ping packet and move on to the next target in a round-robin fashion.</p>

- **arping**
<p>The arping utility sends ARP and/or ICMP requests to the specified host and displays the replies. The host may be specified by its hostname, its IP address, or its MAC address.Arping operates work at the layer 2 (or the link layer of the OSI model) using the Address Resolution Protocol (ARP) for probing hosts. Since ARP is non-routable, this only works for the local network.</p>

- **hping3**

## **Network and Port Scanners**
- **masscan**
- **nmap**

## **OSINT Analysis**
- **spiderfoot**
- **theharvester**

## **Route Analysis**
- **netdiscover**
- **netmask**

## **SMB Analysis**
- **enum4linux**
- **nbtscan**

## **SSL Analysis**
- **dmitry**
- **recon-ng**
- **legion(root)**

# <p align="left"> 02 Vulnerability Analysis</p>
## **Fuzzing Analysis**
- **spike-generic_chunked**
- **spike-generic_listen_tcp**
- **spike-generic_listen_tcp**

## **VoIP Tools**
- **voiphopper**

# <p align="left"> 03 Web Application Analysis</p>
## **CMS & Framework Identification**
- **wpscan**

## **Web Application Proxies**
- **burpsuite**

## **Web Crawlers & Directroty Bruteforce**
- **cutyapt**
- **dirb**
- **wfuzz**

## **Web Vulnerability Scanners**
- **cadaver**
- **davtest**
- **wapiti**

# <p align="left"> 04 Database Assessment</p>
- **sqlmap**

# <p align="left"> 05 Password Attacks</p>
## **Offline Attacks**
- **hashcat**
- **hashid**
- **hash identifier**

## **Online Attacks**
- **hydra**
- **patator**
- **onesixtyone**

## **Passing the Hash Tools**
- **mimiKatz**
- **pth-curl**
- **pth-net**

## **Password Profiling & Worldlists**
- **cewl**
- **crunch**
- **rsmangler**

# <p align="left"> 06 Wireless Attacks</p>
## **802.11 Wireless Tools**
- **bully**
- **fern wifi cracker(root)**
 
## **Bluetooth Tools**
- **aircrack-ng**
- **spooftooph**
- **reaver**

# <p align="left"> 07 Reverse Engineering</p>
- **clang**
- **NASM shell**


# <p align="left"> 08 Exploitation Tools</p>
- **crackmapexec**
- **metasploit framework**
- **msf payload creator**

# <p align="left"> 09 Sniffing & Spoofing</p>
## **Network Sniffers**
- **dnschef**
- **netsniff-ng**
 
## **Spoofing & MITM**
- **rebind**
- **sslsplit**
- **tcpreplay**

# <p align="left"> 10 Post Exploitation</p>
## **OS Backdoors**
- **dbd**
- **powersploit**
 
## **Tunneling & Exfiltration**
- **dns2tcpc**
- **iodine**
- **pwnat**

## **Web Backdoors**
- **laundanum**
- **weevely**

# <p align="left"> 11 Forensics</p>
## **Forensic Craving Tools**
- **magicrescue**
- **scalpel**
- **scorunge-ntfs**
- 
## **Forensic Imaging Tools**
- **guymager(root)**

## **PDF Forensics Tools**
- **pdfid**
- **pdf-parser**

## **Sleuth Kit Suite**
- **autopsy(root)**
- **blkcat**
- **blkcalc**

# <p align="left"> 12 Reporting Tools</p>
- **cutycapt**
- **faraday start**
- **record my desktop**

# <p align="left"> 13 Social Engineering Tools</p>
- **msfpayload creator**
- **social engineering toolkit(root)**
















 
