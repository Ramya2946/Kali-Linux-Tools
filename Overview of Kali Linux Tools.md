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
<p>Wpscan is a vulnerability scanning tool and it can perform brute force attack on the supplied URL. The wpscan works for both HTTP and HTTPS sites. If not provided, it takes HTTP by default.
Features and Utilities:</p>
<p>Checking the version of WordPress used and associated vulnerabilities for that version.</p>
<p>Checks for database dumps that may be openly accessible.</p>
<p>Checks for the WordPress README file.</p>
<p>Brute force usernames and passwords if possible.</p>

## **Web Application Proxies**
- **burpsuite**
<p>Burp Suite is an integrated platform/graphical tool for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.BurpSuite aims to be an all in one set of tools and its capabilities can be enhanced by installing add-ons that are called BApps.
It is the most popular tool among professional web app security researchers and bug bounty hunters. Its ease of use makes it a more suitable choice over free alternatives like OWASP ZAP.</p>


## **Web Crawlers & Directroty Bruteforce**
- **cutyapt**
<p>CutyCapt is a small cross-platform command-line utility to capture WebKit's rendering of a web page into a variety of vector and bitmap formats, including SVG, PDF, PS, PNG, JPEG, TIFF, GIF, and BMP.CutyCapt has many other options to try out like max-wait and delay time and many other things.</p>

- **dirb**
<p>It is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses. DIRB comes with a set of preconfigured attack wordlists for easy usage but you can use your custom wordlists.DIRB can recursively scan directories and look for files with different extensions in a web server. It can automatically detect the Not Found code when it's not the standard 404. It can then export the results to a text file, use session cookies in case the server requires having a valid session, and conduct basic HTTP authentication and upstream proxy among other features.</p>

- **wfuzz**
<p>It is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked directories, servlets, scripts, etc, bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing, etc.It is used to discover common vulnerabilities in web applications through the method of fuzzing. Fuzzing is the concept of trying many known vulnerable inputs with a web application to determine if any of the inputs compromise the web application. It is a great tool to be able to quickly check common vulnerabilities against an application. It is also valuable for testing previously reported vulnerabilities to ensure that regressions don’t occur in an application.</p>

## **Web Vulnerability Scanners**
- **cadaver**
<p>It supports file upload, download, on-screen display, in-place editing, namespace operations (move/copy), collection creation and deletion, property manipulation, and resource locking.
Its operation is similar to the standard BSD ftp(1) client and the Samba Project’s smbclient(1) and includes GnuTLS (HTTPS) support.
WebDAV (Web-based Distributed Authoring and Versioning) is a set of extensions to the HTTP protocol which allow users to collaboratively edit and manage files on remote web servers.</p>

- **davtest**
<p>It tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable.WebDAV is a network protocol which stands for Web-based Distributed Authoring and Versioning that in simpler terms can be said that it is an extension to the HTTP methods and headers which offers the ability to create files and folders, and allow to edit, delete or move them remotely. It also allows transmitting of these files over the internet. It uses port 80 for a simple and an unencrypted connection and makes use of SSL/TLS on port 443 for an encrypted connection.</p>

- **wapiti**
<p>Wapiti allows you to audit the security of your web applications. It performs “black-box” scans, i.e. it does not study the source code of the application but will scan the web pages of the deployed web applications, looking for scripts and forms where it can inject data. Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see if a script is vulnerable.

Wapiti can detect the following vulnerabilities:</p>

<p>Database Injection (PHP/ASP/JSP SQL Injections and XPath Injections)</p>
<p>Cross Site Scripting (XSS) reflected and permanent</p>
<p>File disclosure detection (local and remote include, require, fopen, readfile…)</p>
<p>Command Execution detection (eval(), system(), passtru()…)</p>
<p>XXE (Xml eXternal Entity) injection</p>

# <p align="left"> 04 Database Assessment</p>
- **sqlmap**

<p>sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.</p>

# <p align="left"> 05 Password Attacks</p>
## **Offline Attacks**
- **hashcat**
<p>Hashcat is famous as the fastest password cracker and password recovery utility. Hashcat is designed to break or crack even the most complex passwords in a very less amount of time.

Features of hashcat:</p>
<p>Hashcat is a multi-algorithm based ( MD5, MD4, MySQL, SHA1, NTLM, DCC, etc.).</p>
<p>All attacks can be extended by specialized rules.</p>
<p>The number of threads can be configured.</p>
 
- **hashid**
<p>Identify the different types of hashes used to encrypt data and especially passwords.

hashID is a tool written in Python 3.x which supports the identification of over 175 unique hash types using regular expressions. It is able to identify a single hash or parse a file and identify the hashes within it. There is also a nodejs version of hashID available which is easily set up to provide online hash identification.</p>

- **hash identifier**
<p>Software to identify the different types of hashes used to encrypt data and especially passwords.</p>

## **Online Attacks**
- **hydra**
<p>Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET, HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS, POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP</p>

- **patator**
<p>Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
Currently it supports the following modules:</p>

<p>ftp_login : Brute-force FTP</p>
<p>ssh_login : Brute-force SSH</p>
<p>telnet_login : Brute-force Telnet</p>
<p>smtp_login : Brute-force SMTP</p>
<p>smtp_vrfy : Enumerate valid users using SMTP VRFY</p>

- **onesixtyone**
<p>It is a simple SNMP scanner which sends SNMP requests for the sysDescr value asynchronously with user-adjustable sending times and then logs the responses which gives the description of the software running on the device.Running onesixtyone on a class B network (switched 100Mbs with 1Gbs backbone) with -w 10 gives a performance of 3 seconds per class C, with no dropped packets, and all 65536 IP addresses were scanned in less than 13 minutes.</p>

## **Passing the Hash Tools**
- **mimiKatz**
<p>Mimikatz uses admin rights on Windows to display passwords of currently logged in users in plaintext. It tries and dumps the password from the memory.</p>

## **Password Profiling & Worldlists**
- **cewl**
<p>CeWL (Custom Word List generator) is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.CeWL can also create a list of email addresses found in mailto links. These email addresses can be used as usernames in brute force actions.Another tool provided by CeWL project is FAB (Files Already Bagged). FAB extracts the content of the author/creator fields, from metadata of the some files, to create lists of possible usernames. These usernames can be used in association with the password list generated by CeWL. FAB uses the same metadata extraction techniques that CeWL. Currently, FAB process Office pre 2007, Office 2007 and PDF formats.
CeWL is useful in security tests and forensics investigations. CeWL is pronounced “cool”.</p>

- **crunch**
<p>Crunch is a wordlist generator where you can specify a standard character set or any set of characters to be used in generating the wordlists. The wordlists are created through combination and permutation of a set of characters. You can determine the amount of characters and list size.</p>

- **rsmangler**
<p>RSMangler will take a wordlist and perform various manipulations on it similar to those done by John the Ripper the main difference being that it will first take the input words and generate all permutations and the acronym of the words (in order they appear in the file) before it applies the rest of the mangles.</p>

# <p align="left"> 06 Wireless Attacks</p>
## **802.11 Wireless Tools**
- **bully**
<p>Bully is a new implementation of the WPS brute force attack, written in C. It is conceptually identical to other programs, in that it exploits the (now well known) design flaw in the WPS specification. It has several advantages over the original reaver code. These include fewer dependencies, improved memory and cpu performance, correct handling of endianness, and a more robust set of options.</p>

- **fern wifi cracker(root)**
<p>It contains a Wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks.</p>
 
## **Bluetooth Tools**
- **aircrack-ng**
<p>Aircrack-ng is a tool that comes pre-installed in Kali Linux and is used for wifi network security and hacking. Aircrack is an all in one packet sniffer, WEP and WPA/WPA2 cracker, analyzing tool and a hash capturing tool. It is a tool used for wifi hacking. It helps in capturing the package and reading the hashes out of them and even cracking those hashes by various attacks like dictionary attacks. It supports almost all the latest wireless interfaces. 
It mainly focuses on 4 areas:</p>
<p>Monitoring: Captures cap, packet, or hash files.</p>
<p>Attacking: Performs deauthentication or creates fake access points</p>
<p>Testing: Checking the wifi cards or driver capabilities</p>
<p>Cracking: Various security standards like WEP or WPA PSK.</p>

- **spooftooph**
<p>Spooftooph is designed to automate spoofing or cloning Bluetooth device Name, Class, and Address. Cloning this information effectively allows Bluetooth device to hide in plain site. Bluetooth scanning software will only list one of the devices if more than one device in range shares the same device information when the devices are in Discoverable Mode (specificaly the same Address).</p>

- **reaver**
<p>eaver performs a brute force attack against an access point's WiFi Protected Setup pin number. Once the WPS pin is found, the WPA PSK can be recovered and alternately the AP's wireless settings can be reconfigured.</p>

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
















 
