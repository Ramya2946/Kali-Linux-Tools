# <p align="left"> 01 Information Gathering </p>
## **DNS Analysis**
- **dnsrecon**
<p align="left">DNSRecon is a Python script that provides the ability to perform:
If a DNS Server Cached records for A, AAAA and CNAME,it check all NS Records for Zone Transfers,enumerates General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT),performs common SRV Record enumeration,Checks for Wildcard Resolution,,it performs a PTR Record lookup for a given IP Range or CIDR and records provided a list of host records in a text file to check.</p>

- **dnsenum**
<p align="left"> Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

<p align="left">Get the host’s addresses (A record)</p>
<p align="left">Get the namservers (threaded).</p>
<p align="left">Get the MX record (threaded).</p>
<p align="left">Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).</p>
<p align="left">Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).</p>

- **fierce**
<p align="left">Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It’s really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for. This does not perform exploitation and does not scan the whole internet indiscriminately. It is meant specifically to locate likely targets both inside and outside a corporate network.</p>

## **IDS/IPS Identification**

- **lbd**
<p align="left">Load balancing(lbd) is the technique used in different services for balancing the load across different servers or NICs. It can be in any form. Load balancing can be done to evenly distribute workload through a series of Computer clusters.</p>

- **Wafw00f**
<p align="left">Identifies and fingerprints Web Application Firewall (WAF) products using the following logic:

<p align="left">Sends a normal HTTP request and analyses the response; this identifies a number of WAF solutions.</p>
<p align="left">If that is not successful, it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is.</p>
<p align="left">If that is also not successful, it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to the attacks.</p>

## **Live Host Identification**
- **fping**
<p align="left">ping is a ping like program which uses the Internet Control Message Protocol (ICMP) echo request to determine if a target host is responding. fping differs from ping in that you can specify any number of targets on the command line, or specify a file containing the lists of targets to ping. Instead of sending to one target until it times out or replies, fping will send out a ping packet and move on to the next target in a round-robin fashion.</p>

- **arping**
<p align="left">The arping utility sends ARP and/or ICMP requests to the specified host and displays the replies. The host may be specified by its hostname, its IP address, or its MAC address.Arping operates work at the layer 2 (or the link layer of the OSI model) using the Address Resolution Protocol (ARP) for probing hosts. Since ARP is non-routable, this only works for the local network.</p>

- **hping3**
<p align="left">It is a network tool able to send custom ICMP/UDP/TCP packets and to display target replies like ping does with ICMP replies. It handles fragmentation and arbitrary packet body and size, and can be used to transfer files under supported protocols. Using hping3, you can test firewall rules, perform (spoofed) port scanning, test network performance using different protocols, do path MTU discovery, perform traceroute-like actions under different protocols, fingerprint remote operating systems, audit TCP/IP stacks, etc. hping3 is scriptable using the Tcl language.</p>

## **Network and Port Scanners**
- **masscan**
<p align="left">MASSCAN is TCP port scanner which transmits SYN packets asynchronously and produces results similar to nmap, the most famous port scanner. Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission. It’s a flexible utility that allows arbitrary address and port ranges.</p>

<p align="left">Scalable: Probably the most important feature of Masscan is its ability to transmit up to 10 million packets per second through its asynchronous architecture.</p>
<p align="left">Portability: The software can be compiled and run on all three major operating systems: Windows, MacOS and Linux.</p>
<p align="left">Banner checking: Apart from merely performing port scans, the tool can also complete TCP connections to fetch basic banner information.</p>
<p align="left">Nmap Compatibility: Masscan was developed with the goal of making the tool's usage and output as similar to Nmap's as possible. This enables users to translate their Nmap knowledge quickly.</p>

- **nmap**
<p align="left">Nmap is a utility for network exploration or security auditing. It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification).

<p align="left">Real time information of a network</p>
<p align="left">Detailed information of all the IPs activated on your network</p>
<p align="left">Number of ports open in a network</p>
<p align="left">Provide the list of live hosts</p>
<p align="left">Port, OS and Host scanning</p>

## **OSINT Analysis**
- **spiderfoot**
<p align="left">It contains an open source intelligence (OSINT) automation tool. Its goal is to automate the process of gathering intelligence about a given target, which may be an IP address, domain name, hostname, network subnet, ASN, e-mail address or person’s name.

SpiderFoot can be used offensively, i.e. as part of a black-box penetration test to gather information about the target, or defensively to identify what information you or your organisation are freely providing for attackers to use against you.</p>

- **theharvester**
<p align="left">It contains a tool for gathering subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public sources (search engines, pgp key servers).It also has the capability of doing DNS brute force, reverse IP resolution, and Top-Level Domain (TLD) expansion</p>

## **Route Analysis**
- **netdiscover**
<p align="left">It is an active/passive address reconnaissance tool, mainly developed for those wireless networks without dhcp server, when you are wardriving. It can be also used on hub/switched networks.Built on top of libnet and libpcap, it can passively detect online hosts, or search for them, by actively sending ARP requests.Netdiscover can also be used to inspect your network ARP traffic, or find network addresses using auto scan mode, which will scan for common local networks.Netdiscover uses the OUI table to show the vendor of the each MAC address discovered and is very useful for security checks or in pentests.</p>

- **netmask**
<p align="left">It is a tiny program handy if you work with firewalls or routers occasionally (possibly using this as a helper for shell scripts). It can determine the smallest set of network masks to specify a range of hosts. It can also convert between common IP netmask and address formats.</p>

## **SMB Analysis**
- **enum4linux**
<p align="left">Enum4linux is a tool for enumerating information from Windows and Samba systems.It is written in PERL and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.
Enum4linux is capable of discovering the following:</p>

<p align="left">Password policies on a target</p>
<p align="left">The operating system of a remote target</p>
<p align="left">Shares on a device (drives and folders)</p>
<p align="left">Domain and group membership</p>
<p align="left">User listings</p>
 
- **nbtscan**

## **SSL Analysis**
- **dmitry**
<p align="left">It is a free and open-source tool available on GitHub. The tool is used for information gathering. You can download the tool and install in your Kali Linux. Dmitry stands for DeepMagic Information Gathering Tool. It’s a command-line tool Using Dmitry tool You can collect information about the target, this information can be used for social engineering attacks. It can be used to gather a number of valuable pieces of information.</p>

- **recon-ng**
<p align="left">It is a reconnaissance / OSINT tool with an interface similar to Metasploit. Running recon-ng from the command line speeds up the recon process as it automates gathering information from open sources. Recon-ng has a variety of options to configure, perform recon, and output results to different report types.It has so many modules, database interaction, built-in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted, and we can gather all information.</p>
 
- **legion(root)**
<p align="left">It is a super-extensible and semi-automated network penetration testing framework. Legion is very easy to operate. 

Features of Legion Tool:</p>

<p align="left">GUI with panels and a long list of options that allow pentesters to quickly find and exploit attack vectors on hosts.</p>
<p>It has the feature of real-time auto-saving of project results and tasks.</p>
<p>Legion also provides services like Automatic recon and scanning with NMAP, whataweb, sslyzer, Vulners, webslayer, SMBenum, dirbuster, nikto, Hydra, and almost 100 auto-scheduled scripts are added to it.</p>

# <p align="left"> 02 Vulnerability Analysis</p>
## **Fuzzing Analysis**
- **spike-generic_chunked**
<p align="left">It is actually a fuzzer creation kit, providing an API that allows a user to create their own fuzzers for network based protocols using the C programming language. SPIKE defines a number of primitives that it makes available to C coders, which allows it to construct fuzzed messages called “SPIKES” that can be sent to a network service to hopefully induce errors.</p>

## **VoIP Tools**
- **voiphopper**
<p align="left">It is a GPLv3 licensed security tool, written in C that rapidly runs a VLAN Hop security test. VoIP Hopper is a VoIP infrastructure security testing tool but also a tool that can be used to test the (in)security of VLANs</p>

# <p align="left"> 03 Web Application Analysis</p>
## **CMS & Framework Identification**
- **wpscan**
<p align="left">Wpscan is a vulnerability scanning tool and it can perform brute force attack on the supplied URL. The wpscan works for both HTTP and HTTPS sites. If not provided, it takes HTTP by default.
Features and Utilities:</p>
<p align="left">Checking the version of WordPress used and associated vulnerabilities for that version.</p>
<p align="left">Checks for database dumps that may be openly accessible.</p>
<p align="left">Checks for the WordPress README file.</p>
<p align="left">Brute force usernames and passwords if possible.</p>

## **Web Application Proxies**
- **burpsuite**
<p align="left">It is an integrated platform/graphical tool for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.BurpSuite aims to be an all in one set of tools and its capabilities can be enhanced by installing add-ons that are called BApps.
It is the most popular tool among professional web app security researchers and bug bounty hunters. Its ease of use makes it a more suitable choice over free alternatives like OWASP ZAP.</p>


## **Web Crawlers & Directroty Bruteforce**
- **cutyapt**
<p align="left">CutyCapt is a small cross-platform command-line utility to capture WebKit's rendering of a web page into a variety of vector and bitmap formats, including SVG, PDF, PS, PNG, JPEG, TIFF, GIF, and BMP.CutyCapt has many other options to try out like max-wait and delay time and many other things.</p>

- **dirb**
<p align="left">It is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses. DIRB comes with a set of preconfigured attack wordlists for easy usage but you can use your custom wordlists.DIRB can recursively scan directories and look for files with different extensions in a web server. It can automatically detect the Not Found code when it's not the standard 404. It can then export the results to a text file, use session cookies in case the server requires having a valid session, and conduct basic HTTP authentication and upstream proxy among other features.</p>

- **wfuzz**
<p align="left">It is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked directories, servlets, scripts, etc, bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing, etc.It is used to discover common vulnerabilities in web applications through the method of fuzzing. Fuzzing is the concept of trying many known vulnerable inputs with a web application to determine if any of the inputs compromise the web application. It is a great tool to be able to quickly check common vulnerabilities against an application. It is also valuable for testing previously reported vulnerabilities to ensure that regressions don’t occur in an application.</p>

## **Web Vulnerability Scanners**
- **cadaver**
<p align="left">It supports file upload, download, on-screen display, in-place editing, namespace operations (move/copy), collection creation and deletion, property manipulation, and resource locking.
Its operation is similar to the standard BSD ftp(1) client and the Samba Project’s smbclient(1) and includes GnuTLS (HTTPS) support.
WebDAV (Web-based Distributed Authoring and Versioning) is a set of extensions to the HTTP protocol which allow users to collaboratively edit and manage files on remote web servers.</p>

- **davtest**
<p align="left">It tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable.WebDAV is a network protocol which stands for Web-based Distributed Authoring and Versioning that in simpler terms can be said that it is an extension to the HTTP methods and headers which offers the ability to create files and folders, and allow to edit, delete or move them remotely. It also allows transmitting of these files over the internet. It uses port 80 for a simple and an unencrypted connection and makes use of SSL/TLS on port 443 for an encrypted connection.</p>

- **wapiti**
<p align="left">Wapiti allows you to audit the security of your web applications. It performs “black-box” scans, i.e. it does not study the source code of the application but will scan the web pages of the deployed web applications, looking for scripts and forms where it can inject data. Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see if a script is vulnerable.

Wapiti can detect the following vulnerabilities:</p>

<p align="left">Database Injection (PHP/ASP/JSP SQL Injections and XPath Injections)</p>
<p align="left">Cross Site Scripting (XSS) reflected and permanent</p>
<p align="left">File disclosure detection (local and remote include, require, fopen, readfile…)</p>
<p align="left">Command Execution detection (eval(), system(), passtru()…)</p>
<p align="left">XXE (Xml eXternal Entity) injection</p>

# <p align="left"> 04 Database Assessment</p>
- **sqlmap**

<p align="left">It is to detect and take advantage of SQL injection vulnerabilities in web applications. Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.</p>

# <p align="left"> 05 Password Attacks</p>
## **Offline Attacks**
- **hashcat**
<p align="left">It is famous as the fastest password cracker and password recovery utility. Hashcat is designed to break or crack even the most complex passwords in a very less amount of time.

Features of hashcat:</p>
<p align="left">Hashcat is a multi-algorithm based ( MD5, MD4, MySQL, SHA1, NTLM, DCC, etc.).</p>
<p align="left">All attacks can be extended by specialized rules.</p>
<p align="left">The number of threads can be configured.</p>
 
- **hashid**
<p align="left">Identify the different types of hashes used to encrypt data and especially passwords.

hashID is a tool written in Python 3.x which supports the identification of over 175 unique hash types using regular expressions. It is able to identify a single hash or parse a file and identify the hashes within it. There is also a nodejs version of hashID available which is easily set up to provide online hash identification.</p>

- **hash identifier**
<p align="left">Software to identify the different types of hashes used to encrypt data and especially passwords.</p>

## **Online Attacks**
- **hydra**
<p align="left">It is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET, HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS, POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP</p>

- **patator**
<p align="left">Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
Currently it supports the following modules:</p>

<p align="left">ftp_login : Brute-force FTP</p>
<p align="left">ssh_login : Brute-force SSH</p>
<p align="left">telnet_login : Brute-force Telnet</p>
<p align="left">smtp_login : Brute-force SMTP</p>
<p align="left">smtp_vrfy : Enumerate valid users using SMTP VRFY</p>

- **onesixtyone**
<p align="left">It is a simple SNMP scanner which sends SNMP requests for the sysDescr value asynchronously with user-adjustable sending times and then logs the responses which gives the description of the software running on the device.Running onesixtyone on a class B network (switched 100Mbs with 1Gbs backbone) with -w 10 gives a performance of 3 seconds per class C, with no dropped packets, and all 65536 IP addresses were scanned in less than 13 minutes.</p>

## **Passing the Hash Tools**
- **mimiKatz**
<p align="left">It uses admin rights on Windows to display passwords of currently logged in users in plaintext. It tries and dumps the password from the memory.</p>

## **Password Profiling & Worldlists**
- **cewl**
<p align="left">(Custom Word List generator)It is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper. Optionally, CeWL can follow external links.CeWL can also create a list of email addresses found in mailto links. These email addresses can be used as usernames in brute force actions.Another tool provided by CeWL project is FAB (Files Already Bagged). FAB extracts the content of the author/creator fields, from metadata of the some files, to create lists of possible usernames. These usernames can be used in association with the password list generated by CeWL. FAB uses the same metadata extraction techniques that CeWL. Currently, FAB process Office pre 2007, Office 2007 and PDF formats.
CeWL is useful in security tests and forensics investigations. CeWL is pronounced “cool”.</p>

- **crunch**
<p align="left">It is a wordlist generator where you can specify a standard character set or any set of characters to be used in generating the wordlists. The wordlists are created through combination and permutation of a set of characters. You can determine the amount of characters and list size.</p>

- **rsmangler**
<p align="left">RSMangler will take a wordlist and perform various manipulations on it similar to those done by John the Ripper the main difference being that it will first take the input words and generate all permutations and the acronym of the words (in order they appear in the file) before it applies the rest of the mangles.</p>

# <p align="left"> 06 Wireless Attacks</p>
## **802.11 Wireless Tools**
- **bully**
<p align="left">It is a new implementation of the WPS brute force attack, written in C. It is conceptually identical to other programs, in that it exploits the (now well known) design flaw in the WPS specification. It has several advantages over the original reaver code. These include fewer dependencies, improved memory and cpu performance, correct handling of endianness, and a more robust set of options.</p>

- **fern wifi cracker(root)**
<p align="left">It contains a Wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks.</p>
 
## **Bluetooth Tools**
- **aircrack-ng**
<p align="left">It is a tool that comes pre-installed in Kali Linux and is used for wifi network security and hacking. Aircrack is an all in one packet sniffer, WEP and WPA/WPA2 cracker, analyzing tool and a hash capturing tool. It is a tool used for wifi hacking. It helps in capturing the package and reading the hashes out of them and even cracking those hashes by various attacks like dictionary attacks. It supports almost all the latest wireless interfaces. 
It mainly focuses on 4 areas:</p>
<p>Monitoring: Captures cap, packet, or hash files.</p>
<p>Attacking: Performs deauthentication or creates fake access points</p>
<p>Testing: Checking the wifi cards or driver capabilities</p>
<p>Cracking: Various security standards like WEP or WPA PSK.</p>

- **spooftooph**
<p align="left">It is designed to automate spoofing or cloning Bluetooth device Name, Class, and Address. Cloning this information effectively allows Bluetooth device to hide in plain site. Bluetooth scanning software will only list one of the devices if more than one device in range shares the same device information when the devices are in Discoverable Mode (specificaly the same Address).</p>

- **reaver**
<p align="left">It performs a brute force attack against an access point's WiFi Protected Setup pin number. Once the WPS pin is found, the WPA PSK can be recovered and alternately the AP's wireless settings can be reconfigured.</p>

# <p align="left"> 07 Reverse Engineering</p>
- **clang**
<p align="left">It is a C, C++, Objective C and Objective C++ front-end for the LLVM compiler. Its goal is to offer a replacement to the GNU Compiler Collection (GCC).Clang implements all of the ISO C++ 1998, 11 and 14 standards and also provides most of the support of C++17.
This is a dependency package providing the default clang compiler.</p>

- **NASM shell**
<p align="left">It outputs flat-form binary files, a.out, COFF and ELF Unix object files, and Microsoft 16-bit DOS and Win32 object files.
Also included is NDISASM, a prototype x86 binary-file disassembler which uses the same instruction table as NASM.NASM is released under the GNU Lesser General Public License (LGPL).Most programs consist of directives followed by one or more sections. Lines can have an optional label. Most lines have an instruction followed by zero or more operands.</p>


# <p align="left"> 08 Exploitation Tools</p>
- **crackmapexec**
<p align="left">It is a swiss army knife for pentesting Windows/Active Directory environments.From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.
The biggest improvements over the above tools are:</p>

<p align="left">Pure Python script, no external tools required</p>
<p align="left">Fully concurrent threading</p>
<p align="left">Uses ONLY native WinAPI calls for discovering sessions, users, dumping SAM hashes etc…</p>
<p align="left">Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc…)</p>
<p align="left">Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily keep track of credential sets and gain additional situational awareness in large environments.</p>
 
- **metasploit framework**
<p align="left">It is an open source platform that supports vulnerability research, exploit development, and the creation of custom security tools.
  Metasploit framework that allows red teamers to perform reconnaissance, scan, enumerate, and exploit vulnerabilities for all types of applications, networks, servers, operating systems, and platforms.Even though the main functionality of Metasploit focuses on pre- and post-exploitation pentesting tasks, it is also helpful in exploit development and vulnerability research.</p>
  
- **msf payload creator**
<p align="left">MSFvenom Payload Creator (MSFPC) is a wrapper to generate multiple types of payloads, based on the user’s choice. The idea is to be as simple as possible (only requiring one input) to produce their payload.</p>

# <p align="left"> 09 Sniffing & Spoofing</p>
## **Network Sniffers**
- **dnschef**
<p align="left">DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka “Fake DNS”) is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for “badguy.com” to point to a local machine for termination or interception instead of a real host somewhere on the Internet.Domain Name System (DNS) is a distributed naming system for computers, services, or any resource connected to the Internet or private network. Providing fake DNS addresses can redirect traffic to other desired locations.</p>

- **netsniff-ng**
<p align="left">netsniff-ng is a free Linux network analyzer and networking toolkit originally written by Daniel Borkmann. Its gain of performance is reached by zero-copy mechanisms for network packets, so that the Linux kernel does not need to copy packets from kernel space to user space via system calls such as recvmsg.A fast zero-copy analyzer, pcap capturing and replaying tool</p>

 ## **Spoofing & MITM**
- **rebind**
<p align="left">Rebind is a tool that implements the multiple A record DNS rebinding attack. Although this tool was originally written to target home routers, it can be used to target any public (non RFC1918) IP address.Rebind provides an external attacker access to a target router’s internal Web interface. This tool works on routers that implement the weak end system model in their IP stack, have specifically configured firewall rules, and who bind their Web service to the router’s WAN interface. Note that remote administration does not need to be enabled for this attack to work. All that is required is that a user inside the target network surf to a Web site that is controlled, or has been compromised, by the attacker.</p>

- **sslsplit**
<p align="left">It is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit.It complements a MITM attack and extract information from an encrypted communication.</p>

- **tcpreplay**
<p align="left">Tcpreplay is aimed at testing the performance of a NIDS by replaying real background network traffic in which to hide attacks. Tcpreplay allows you to control the speed at which the traffic is replayed, and can replay arbitrary tcpdump traces. Unlike programmatically-generated artificial traffic which doesn’t exercise the application/protocol inspection that a NIDS performs, and doesn’t reproduce the real-world anomalies that appear on production networks (asymmetric routes, traffic bursts/lulls, fragmentation, retransmissions, etc.), tcpreplay allows for exact replication of real traffic seen on real networks. It included the following executables tcpprep, tcprewrite, tcpreplay-edit, tcpbridge and pcap based captures are possible.</p>

# <p align="left"> 10 Post Exploitation</p>
## **OS Backdoors**
- **dbd**
<p align="left">dbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. dbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. dbd supports TCP/IP communication only. Source code and binaries are distributed under the GNU General Public License.</p>

- **powersploit**
 <p align="left">PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.It is an open source, offensive security framework comprised of PowerShell modules and scripts that perform a wide range of tasks related to penetration testing such as code execution, persistence, bypassing anti-virus, recon, and exfiltration.</p>
 
## **Tunneling & Exfiltration**
- **dns2tcpc**
<p align="left">dns2tcp is using dns (asking for TXT records within a (sub)domain) to archive the goal we need to create a NS record for a new subdomain pointing to the address of our server : dns2tcp.kali.org. IN NS lab.kali.org.There is no need for a DNS server installation. It is a tool for relaying TCP connections over DNS. Among other things, it can be used to bypass captive portals (e.g. hotels, airport, ...) when only port 53/udp is allowed by the firewall.</p>
<p>The client starts dns2tcpc (dns2tcp client) and requires the remote ssh resource (-r ssh) through local port 2222/tcp (-l 2222). </p>
<p>It encapsulates the TCP traffic into fake DNS requests. Then, it opens a SOCKS proxy on port 1080 through the previously created tunnel.</p>
<p>he fake DNS requests are delegated to the remote dns2tcp server that decapsulates the fake requests and send the request to the requested resource.</p>
<p>The response is sent to the remote dns2tcp server that encapsulates it into fake DNS responses</p>
<p>The client decapsulates the fake DNS response and serves the HTTP response.</p>

- **iodine**
<p>Iodine is a tool for tunneling Internet protocol version 4 (IPV4) traffic over the DNS protocol to circumvent firewalls, network security groups, and network access lists while evading detection.</p>
 
- **pwnat**
<p>pwnat, pronounced “poe-nat”, is a tool that allows any number of clients behind NATs to communicate with a server behind a separate NAT with no port forwarding and no DMZ setup on any routers in order to directly communicate with each other. The server does not need to know anything about the clients trying to connect.	It is a NAT to NAT client-server communication.</p>

## **Web Backdoors**
- **laundanum**
<p>Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.audanum is not an application, but rather a repository of inject-able files.  On its own, it doesn’t do anything.  These files can be deployed to a target machine and then executed to perform specific functionality</p>

- **weevely**
<p>Weevely is a stealth PHP web shell that simulate telnet-like connection. It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.Its terminal executes arbitrary remote code through the small footprint PHP agent that sits on the HTTP server. Over 30 modules shape an adaptable web administration and post-exploitation backdoor for access maintenance, privilege escalation, and network lateral movement, even in the restricted environment.</p>

# <p align="left"> 11 Forensics</p>
## **Forensic Craving Tools**
- **magicrescue**
<p>Magic Rescue scans a block device for file types it knows how to recover and calls an external program to extract them. It looks at “magic bytes” (file patterns) in file contents, so it can be used both as an undelete utility and for recovering a corrupted drive or partition. As long as the file data is there, it will find it.Magic Rescue uses files called ‘recipes’. These files have strings and commands to identify and extract data from devices or forensics images. So, you can write your own recipes. Currently, there are the following recipes: avi, canon-cr2, elf, flac, gpl, gzip, jpeg-exif, jpeg-jfif, mbox, mbox-mozilla-inbox, mbox-mozilla-sent, mp3-id3v1, mp3-id3v2, msoffice, nikon-raw, perl, png, ppm, sqlite and zip.</p>

- **scalpel**
<p>scalpel is a fast file carver that reads a database of header and footer definitions and extracts matching files from a set of image files or raw device files. scalpel is filesystem-independent and will carve files from FAT16, FAT32, exFAT, NTFS, Ext2, Ext3, Ext4, JFS, XFS, ReiserFS, raw partitions, etc. Scalpel aims to address the high CPU and RAM usage issues of Foremost when carving data.This forensic tool carves all the files and indexes those applications which run on Linux and windows. It supports multithreading execution on multiple core systems, which help in quick executions. File carving is performed in fragments such as regular expressions or binary strings.</p>

- **scorunge-ntfs**
<p>Scrounge NTFS is a data recovery program for NTFS filesystems. It reads each block of the hard disk and try to rebuild the original filesystem tree into a directory. This package is useful in forensics investigations.It helps in retrieving data from corrupted NTFS disks or partitions. It rescues data from a corrupted file system to a new working file system.</p>

## **Forensic Imaging Tools**
- **guymager(root)**
<p>This forensic utility is used to acquire media for forensic imagery and has a graphical user interface. Due to its multi-threaded data processing and compression, it is a very fast tool. This tool also supports cloning. It generates flat, AFF, and EWF images. The UI is very easy to use.The forensic imager contained in this package, guymager, was designed to support different image file formats, to be most user-friendly and to run really fast.</p>

## **PDF Forensics Tools**
- **pdfid**
<p>This forensic tool is used in pdf files. The tool scans pdf files for specific keywords, which allows you to identify executable codes when opened. This tool solves the basic problems associated with pdf files. The suspicious files are then analyzed with the pdf-parser tool.This tool is not a PDF parser, but it will scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.</p>

- **pdf-parser**
<p>This tool is one of the most important forensic tools for pdf files. pdf-parser parses a pdf document and distinguishes the important elements utilized during its analysis, and this tool does not render that pdf document.This tool will parse a PDF document to identify the fundamental elements used in the analyzed file. It will not render a PDF document.</p>

## **Sleuth Kit Suite**
- **autopsy(root)**
<p>An autopsy is all in one forensic utility for fast data recovery and hash filtering. This tool carves deleted files and media from unallocated space using PhotoRec. It can also extract EXIF extension multimedia. Autopsy scans for compromise indicator using STIX library. It is available in the command line as well as GUI interface.The Autopsy Forensic Browser is a graphical interface to the command line digital forensic analysis tools in The Sleuth Kit. Together, The Sleuth Kit and Autopsy provide many of the same features as commercial digital forensics tools for the analysis of Windows and UNIX file systems (NTFS, FAT, FFS, EXT2FS, and EXT3FS)</p>

- **blkcat**
<p>The blkcat tool is a quick and efficient forensic tool packaged inside Kali. The purpose of this tool is to display the contents of the data stored in a file system’s disk image. The output displays the number of data units, starting with the unit’s main address and prints, into different formats that can be specified and sorted. By default, the output format is raw, and it is also called dcat.</p>

- **blkcalc**
<p>The blkcalc tool is a forensic tool that converts unallocated disk points to regular disk points. This program creates a point number that maps two images. One of these images is normal, and the other contains unallocated point numbers of the first image. This tool can support many file system types. If a file system is not defined at the start, blkcalc has the unique feature of autodetection methods to find the file system type.</p>

# <p align="left"> 12 Reporting Tools</p>

- **faraday start**
<p>Faraday is a GUI application that consists of a ZSH terminal and a sidebar with details about your workspaces and hosts.When Faraday supports the command you are running, it will automatically detect it and import the results. In the example below, the original nmap command that was entered was nmap -A 192.168.0.7, which Faraday converted on the fly.</p>

- **record my desktop**
<p>The application produces an ogg-encapsulated theora-vorbis file. recordMyDesktop tries to be as unobstrusive as possible by proccessing only regions of the screen that have changed.The program is separated into two parts; a command line tool that performs the tasks of capturing and encoding, and an interface that exposes the program functionality graphically. There are two front-ends written in python with pyGtk (gtk-recordMyDesktop) and pyQt4 (qt-recordMyDesktop). RecordMyDesktop also offers the ability to record audio through ALSA, OSS or the JACK audio server. RecordMyDesktop only outputs to Ogg using Theora for video and Vorbis for audi</p>

# <p align="left"> 13 Social Engineering Tools</p>
- **social engineering toolkit(root)**
<p>The Social-Engineer Toolkit (SET) is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of time. These kind of tools use human behaviors to trick them to the attack vectors.</p>
















 
