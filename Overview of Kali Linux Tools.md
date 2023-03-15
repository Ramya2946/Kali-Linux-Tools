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
<p>ping is a ping like program which uses the Internet Control Message Protocol (ICMP) echo request to determine if a target host is responding. fping differs from ping in that you can specify any number of targets on the command line, or specify a file containing the lists of targets to ping. Instead of sending to one target until it times out or replies, fping will send out a ping packet and move on to the next target in a round-robin fashion.</p>

- **arping**
<p>The arping utility sends ARP and/or ICMP requests to the specified host and displays the replies. The host may be specified by its hostname, its IP address, or its MAC address.Arping operates work at the layer 2 (or the link layer of the OSI model) using the Address Resolution Protocol (ARP) for probing hosts. Since ARP is non-routable, this only works for the local network.</p>

- **hping3**
<p>It is a network tool able to send custom ICMP/UDP/TCP packets and to display target replies like ping does with ICMP replies. It handles fragmentation and arbitrary packet body and size, and can be used to transfer files under supported protocols. Using hping3, you can test firewall rules, perform (spoofed) port scanning, test network performance using different protocols, do path MTU discovery, perform traceroute-like actions under different protocols, fingerprint remote operating systems, audit TCP/IP stacks, etc. hping3 is scriptable using the Tcl language.</p>

## **Network and Port Scanners**
- **masscan**
MASSCAN is TCP port scanner which transmits SYN packets asynchronously and produces results similar to nmap, the most famous port scanner. Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission. It’s a flexible utility that allows arbitrary address and port ranges.

<p>Scalable: Probably the most important feature of Masscan is its ability to transmit up to 10 million packets per second through its asynchronous architecture.</p>
<p>Portability: The software can be compiled and run on all three major operating systems: Windows, MacOS and Linux.</p>
<p>Banner checking: Apart from merely performing port scans, the tool can also complete TCP connections to fetch basic banner information.</p>
<p>Nmap Compatibility: Masscan was developed with the goal of making the tool's usage and output as similar to Nmap's as possible. This enables users to translate their Nmap knowledge quickly.</p>

- **nmap**
<p>Nmap is a utility for network exploration or security auditing. It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification).

<p>Real time information of a network</p>
<p>Detailed information of all the IPs activated on your network</p>
<p>Number of ports open in a network</p>
<p>Provide the list of live hosts</p>
<p>Port, OS and Host scanning</p>

## **OSINT Analysis**
- **spiderfoot**
<p>This package contains an open source intelligence (OSINT) automation tool. Its goal is to automate the process of gathering intelligence about a given target, which may be an IP address, domain name, hostname, network subnet, ASN, e-mail address or person’s name.

SpiderFoot can be used offensively, i.e. as part of a black-box penetration test to gather information about the target, or defensively to identify what information you or your organisation are freely providing for attackers to use against you.</p>

- **theharvester**
<p>It contains a tool for gathering subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public sources (search engines, pgp key servers).It also has the capability of doing DNS brute force, reverse IP resolution, and Top-Level Domain (TLD) expansion</p>

## **Route Analysis**
- **netdiscover**
<p>Netdiscover is an active/passive address reconnaissance tool, mainly developed for those wireless networks without dhcp server, when you are wardriving. It can be also used on hub/switched networks.

Built on top of libnet and libpcap, it can passively detect online hosts, or search for them, by actively sending ARP requests.

Netdiscover can also be used to inspect your network ARP traffic, or find network addresses using auto scan mode, which will scan for common local networks.

Netdiscover uses the OUI table to show the vendor of the each MAC address discovered and is very useful for security checks or in pentests.</p>

- **netmask**
<p>It is a tiny program handy if you work with firewalls or routers occasionally (possibly using this as a helper for shell scripts). It can determine the smallest set of network masks to specify a range of hosts. It can also convert between common IP netmask and address formats.</p>

## **SMB Analysis**
- **enum4linux**
<p>Enum4linux is a tool for enumerating information from Windows and Samba systems.

It is written in PERL and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.
Enum4linux is capable of discovering the following:</p>

<p>Password policies on a target</p>
<p>The operating system of a remote target</p>
<p>Shares on a device (drives and folders)</p>
<p>Domain and group membership</p>
<p>User listings</p>
 
- **nbtscan**

## **SSL Analysis**
- **dmitry**
<p>It is a free and open-source tool available on GitHub. The tool is used for information gathering. You can download the tool and install in your Kali Linux. Dmitry stands for DeepMagic Information Gathering Tool. It’s a command-line tool Using Dmitry tool You can collect information about the target, this information can be used for social engineering attacks. It can be used to gather a number of valuable pieces of information.</p>

- **recon-ng**
<p>Recon-ng is a reconnaissance / OSINT tool with an interface similar to Metasploit. Running recon-ng from the command line speeds up the recon process as it automates gathering information from open sources. Recon-ng has a variety of options to configure, perform recon, and output results to different report types.It has so many modules, database interaction, built-in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted, and we can gather all information.</p>
 
- **legion(root)**
<p>Legion tool is a super-extensible and semi-automated network penetration testing framework. Legion is very easy to operate. 

Features of Legion Tool:</p>

<p>GUI with panels and a long list of options that allow pentesters to quickly find and exploit attack vectors on hosts.</p>
<p>It has the feature of real-time auto-saving of project results and tasks.</p>
<p>Legion also provides services like Automatic recon and scanning with NMAP, whataweb, sslyzer, Vulners, webslayer, SMBenum, dirbuster, nikto, Hydra, and almost 100 auto-scheduled scripts are added to it.</p>

# <p align="left"> 02 Vulnerability Analysis</p>
## **Fuzzing Analysis**
- **spike-generic_chunked**
<p>SPIKE is actually a fuzzer creation kit, providing an API that allows a user to create their own fuzzers for network based protocols using the C programming language. SPIKE defines a number of primitives that it makes available to C coders, which allows it to construct fuzzed messages called “SPIKES” that can be sent to a network service to hopefully induce errors.</p>

## **VoIP Tools**
- **voiphopper**
<p>It is a GPLv3 licensed security tool, written in C that rapidly runs a VLAN Hop security test. VoIP Hopper is a VoIP infrastructure security testing tool but also a tool that can be used to test the (in)security of VLANs</p>

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
















 
