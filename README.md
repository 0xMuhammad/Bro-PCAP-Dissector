# Bro-PCAP-Dissector
Bro script to dissect PCAP traces



# Bro-PCAP-Dissector
Bro script to dissect PCAP files in a way that facilitates active threat hunting by employing stack counting techniques. The script accepts PCAP fileas an input, scans the existence of major network protocols (i.e. HTTP,DNS,SMB,RDP,SSH,SSL,FTP and IRC) and produce sorted and counted lists of interesting fields/headers upon the existence of any of the previous protocols.

Running the script using this command "bro -C -r trace.pcap dissector.bro" produces the following samples (different PCAPs) output

Running the script using this command "bro -C -r trace.pcap dissector.bro" produces the following samples (different PCAPs) output
==========================================================		
Bytes Downloaded > {3000000 Bytes / 3 MB}		
==========================================================
Format: size (Descending), client IP, server IP, server port
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00001.pcap @ http://bit.ly/2mWr0kx

	5366941               192.168.203.64   <-------  192.168.202.68   : 55554/tcp
	5184633               192.168.204.70   <-------  192.168.202.68   : 55554/tcp
	4203410               192.168.204.45   <-------  192.168.202.68   : 55554/tcp
	4091323               192.168.27.100   <-------  192.168.202.110  : 4444/tcp
	4086085               192.168.28.100   <-------  192.168.203.45   : 54321/tcp
	3497984               192.168.27.100   <-------  192.168.203.45   : 9898/tcp
	3497812               192.168.24.100   <-------  192.168.203.45   : 54322/tcp
	3496305               192.168.26.100   <-------  192.168.203.45   : 54344/tcp
	3476280               192.168.24.100   <-------  192.168.202.110  : 4444/tcp

 
==========================================================
Bytes Uploaded > {1000000 Bytes / 1 MB}
==========================================================
Format: size (Descending), client IP, server IP, server port
</br>
Results from: ismellpackets/Hidden.pcap @ http://bit.ly/2lSdxt8


	1510081441            192.168.4.5      -------> 207.171.185.200  : 443/tcp
	1436668500            192.168.4.5      -------> 74.125.239.3     : 443/tcp
	1429743201            192.168.4.5      -------> 207.171.187.117  : 443/tcp
	1068033242            192.168.4.5      -------> 23.212.8.120     : 80/tcp
	742832115             192.168.4.5      -------> 207.171.187.117  : 443/tcp
	729590415             192.168.4.5      -------> 207.171.187.117  : 443/tcp
	251404609             192.168.4.5      -------> 23.67.247.112    : 80/tcp
	8393910               192.168.4.5      -------> 207.171.187.117  : 443/tcp
 


==========================================================
Conn Duration > {600 Second / 10 Minutes}
==========================================================
Format: session duration in seconds (Descending) , client IP, server IP, server port
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00001.pcap @ http://bit.ly/2maxlsD

	1840                  192.168.202.68   <------->     192.168.28.203   : 22/tcp
	1788                  192.168.202.109  <------->     192.168.22.254   : 22/tcp
	1765                  192.168.204.70   <------->     192.168.202.68   : 55554/tcp
	1752                  192.168.202.109  <------->     192.168.23.254   : 22/tcp
	1680                  192.168.28.100   <------->     192.168.203.45   : 54321/tcp
	1650                  192.168.202.109  <------->     192.168.24.254   : 22/tcp
	1645                  192.168.28.100   <------->     192.168.204.45   : 1025/tcp
	1632                  192.168.28.100   <------->     192.168.202.112  : 1025/tcp
	1623                  192.168.202.109  <------->     192.168.25.254   : 22/tcp
	1567                  192.168.202.109  <------->     192.168.27.254   : 22/tcp
	1533                  192.168.202.109  <------->     192.168.28.254   : 22/tcp
	1522                  192.168.24.100   <------->     192.168.202.90   : 4499/tcp
	1470                  192.168.24.100   <------->     192.168.202.90   : 4499/tcp
	1445                  192.168.202.109  <------->     192.168.21.254   : 22/tcp
	1435                  192.168.24.100   <------->     192.168.203.45   : 1025/tcp

 
==========================================================
Conn Listening_TCP_Ports_on_Private_IPs
==========================================================
Format: # of sessions (Ascending), tcp port, server IP, protocol
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00003.pcap @ http://bit.ly/2maxlsD

	1             8089/tcp  listening on  192.168.22.253   ssl
	1             8000/tcp  listening on  192.168.25.253   http
	1             5432/tcp  listening on  192.168.203.45   -
	1             139/tcp   listening on  192.168.25.102   ntlm,gssapi,smb,dce_rpc
	1             22/tcp    listening on  192.168.28.203   ssh
	1             22/tcp    listening on  192.168.21.254   ssh
	1             445/tcp   listening on  192.168.27.100   ntlm,smb,dce_rpc
	1             80/tcp    listening on  192.168.22.253   http
	1             445/tcp   listening on  192.168.25.102   ntlm,gssapi,smb,dce_rpc
	1             80/tcp    listening on  192.168.21.202   http
	1             443/tcp   listening on  192.168.201.2    ssl
	1             8080/tcp  listening on  192.168.23.203   http
	1             80/tcp    listening on  192.168.28.101   http
	2             55553/tcp listening on  192.168.202.68   ssl
	2             80/tcp    listening on  192.168.23.101   http
	2             80/tcp    listening on  192.168.25.202   http
	3             22/tcp    listening on  192.168.23.101   ssh
	4             445/tcp   listening on  192.168.27.100   ntlm,smb
	4             80/tcp    listening on  192.168.25.102   http
	5             443/tcp   listening on  192.168.25.253   ssl
	5             443/tcp   listening on  192.168.22.253   ssl
	7             443/tcp   listening on  192.168.22.254   ssl
	13            80/tcp    listening on  192.168.202.78   http
	17            443/tcp   listening on  192.168.25.254   ssl
	18            22/tcp    listening on  192.168.22.253   ssh


 
==========================================================
Conn Listening_TCP_Ports_on_Public_IPs
==========================================================
Format: # of sessions (Ascending), tcp port, protocol 
</br>
Results from: Malware Traffic Analysis / 2015-06-30-traffic-analysis-exercise.pcap @ http://bit.ly/2lSbbdH

	1             6998/tcp  -------> -
	3             80/tcp    -------> http
	9             443/tcp   -------> ssl


 

==========================================================
HTTP Odd_Hosts
==========================================================
Format: # of occurence (Ascending), odd HTTP hosts
</br>
Results from: Malware Traffic Analysis / 2016-05-13-traffic-analysis-exercise.pcap @ http://bit.ly/2mvlhVA

 
	1             magusserver.top
	1             a.topgunn.photography
	1             widgets.amung.us
	1             whos.amung.us
	1             ckea.ca
	2             x.ss2.us
	2             g00.co
	3             mohecy.tk
	4             185.82.202.170
	6             ululataque-forstbea.bondcroftatvs.co.uk
	7             e7qx9y.he6gnm.top
	15            www.emidioleite.com.br
	23            5.34.183.40



==========================================================
HTTP Referrers
==========================================================
Format: # of occurence (Ascending), TLD part of HTTP referrer
</br>
Results from: Malware Traffic Analysis / 2016-03-30-traffic-analysis-exercise.pcap @ http://bit.ly/2mLFlDN


	1             ztjyuncjqvi1e.com
	1             www.ecb.europa.eu
	2             www.google.com
	2             leadback.advertising.com
	2             folesd.tk
	2             scoring33.com
	2             lemepackrougue.com
	3             wincepromotional.com
	3             rmfytrwemvvk.com
	3             fireman.carsassurance.info
	4             9e886e6c4bf39d002b00-b32e53c17e846b593b21b014f11dc266.r14.cf2.rackcdn.com
	4             8def3da737b3b1117f05-2484ec98d956dd65605480d10636de6f.r11.cf1.rackcdn.com
	6             score.feed-xml.com
	8             trafficinside.me
	9             fast.twc.demdex.net
	10            popcash.net
	16            ip.casalemedia.com
	21            cmap.uac.ace.advertising.com
	23            xxxsexcamera.club
	29            -
	63            thingstodo.viator.com
	83            webmail.roadrunner.com

 
==========================================================
HTTP User-Agents
==========================================================
Format: # of occuernce (Ascending), HTTP user-agent
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00010.pcap @ http://bit.ly/2maxlsD



	1             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000889)
	2             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000904)
	2             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000915)
	2             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000805)
	2             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000918)
	2             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000878)
	2             login
	3             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000258)
	4             Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SIMBAR={7DB0F6DE-8DE7-4841-9084-28FA914B0F2E}; SLCC1; .N
	4             Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:11.0) Gecko/20100101 Firefox/11.0
	5             Fastream NETFile Server
	5             Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000408)
	10            webmin
	10            NESSUS::SOAP
	15            Nessus SOAP v0.0.1 (Nessus.org)
	16            Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2
	16            Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko/20100101 Firefox/11.0
	17            Mozilla/5.0 (Windows NT 6.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1
	24            Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.11) Gecko/20101013 Ubuntu/9.04 (jaunty) Firefox/3.6.11
	39            Mozilla/5.0 (X11; Linux i686 on x86_64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2
	48            Mozilla/5.0 (X11; Linux i686; rv:10.0.2) Gecko/20100101 Firefox/10.0.2
	75            Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.79 Safari/535.11
	89            Mozilla/5.0 (X11; Linux i686; rv:5.0.1) Gecko/20100101 Firefox/5.0.1
	96            Nessus
	199           Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0.2) Gecko/20100101 Firefox/10.0.2
	281           Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2
	405           Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
	649           Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)
	1369          Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)
	6341          -
	8081          Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)
	17520         Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)
	481029        DirBuster-0.12 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)


==========================================================
HTTP Methods
==========================================================
Format: # of occurence (Ascending), HTTP request method 
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00006.pcap @ http://bit.ly/2maxlsD
 
	1             SEARCH
	2             PROPFIND
	3             OPTIONS
	3             DESCRIBE
	42            PUT
	76            DELETE
	76            HEAD
	16896         GET
	42856         POST

==========================================================
HTTP Response_Codes
==========================================================
Format: # of occurence (Ascending), HTTP response status code 
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00009.pcap @ http://bit.ly/2maxlsD


	1             SEARCH
	2             PROPFIND
	4             TRACE
	53            PUT
	118           DELETE
	488           OPTIONS
	624           POST
	21154         GET
	392084        HEAD
 
==========================================================
HTTP Client_Requests
==========================================================
 Format: # of HTTP requests (Ascending), client IP
</br>
Results from: Malware Traffic Analysis /  2014-12-15-traffic-analysis-exercise.pcap @ http://bit.ly/2lNMcYi
 
 
	46            192.168.204.137
	59            192.168.204.139
	122           192.168.204.146

==========================================================
DNS NXDOMAIN_Queries
==========================================================
Format: # of queries to NX domains (Ascending), client IP
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00003.pcap @ http://bit.ly/2maxlsD


	1             192.168.202.76
	1             192.168.202.92
	1             192.168.202.85
	1             192.168.202.102
	1             192.168.202.112
	2             192.168.203.63
	2             192.168.202.115
	3             192.168.204.60
	4             192.168.203.61
	7             192.168.202.75
	9             192.168.202.83
	10            192.168.202.100
	12            192.168.202.108
	14            192.168.202.94
	17            192.168.202.77
	28            192.168.202.103
	141           192.168.204.70
 
 ==========================================================
DNS Client_Queries
==========================================================
Format: # of DNS queries (Ascending), client IP
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition /maccdc2012_00001.pcap @ http://bit.ly/2maxlsD

	1             192.168.202.77
	1             fe80::223:dfff:fe97:4e12
	1             192.168.22.152
	1             192.168.21.152
	1             fe80::c62c:3ff:fe37:efc
	1             192.168.28.152
	2             fe80::ba8d:12ff:fe53:a8d8
	2             192.168.28.103
	2             192.168.26.152
	3             192.168.202.94
	4             192.168.202.71
	5             192.168.202.110
	13            fe80::3e07:54ff:fe1c:a665
	25            192.168.202.102
	31            192.168.202.115
	108           192.168.204.45
 
==========================================================
DNS Query_Types
==========================================================
Format: # of occurence (Ascending), DNS query type
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition /maccdc2012_00006.pcap @ http://bit.ly/2maxlsD

	8             *
	10            PTR
	16            A
	99            AXFR
 
 
==========================================================
DNS Odd_Queries
==========================================================
Format: # of occurence (Ascending), odd DNS query
</br>
Results from: Malware Traffic Analysis / 2015-05-08-traffic-analysis-exercise.pcap @ http://bit.ly/2lS8g4L

	1             runlove.us
	1             r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in
	1             7oqnsnzwwnm6zb7y.gigapaysun.com
	1             ip-addr.es
	1             ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in
	1             va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in
	1             kritischerkonsum.uni-koeln.de

==========================================================
SMB2 Sessions
==========================================================
Format: # of sessions (Ascending), client IP, server IP, server port

 	494           x.x.x.x    -------> x.x.x.x     :  445/tcp
	532           x.x.x.x    -------> x.x.x.x     :  445/tcp
 
==========================================================
SMB2 Usernames
==========================================================
Format: # of occurence (Ascending), domain\username

	21            Domain            \          Username1
	494           Domain            \          Username2
 
==========================================================
SMB2 Hostnames
==========================================================
Format: # of occurence (Ascending), SMB hostname

 	21            ServerABC
	494           ServerXYZ
 
==========================================================
SMB2 File_Actions
==========================================================
Format: # of occurence (Ascending), file action

	2             SMB::FILE_WRITE
	52            SMB::FILE_READ
	188           SMB::FILE_CLOSE
	252           SMB::FILE_OPEN
 
==========================================================
SMB2 File_Names
==========================================================
Format: # of occurence (Ascending), SMB file name

	1             ui\SwDRM.dll
	1             desktop.ini
	1             inetpub\wwwroot\iis-85.png:Zone.Identifier
	4             inetpub\history\CFGHISTORY_0000000004
	4             inetpub\temp
	4             inetpub\logs\LogFiles\W3SVC1
	4             inetpub\history\CFGHISTORY_0000000002
	4             inetpub\logs\LogFiles
	4             inetpub\history
	4             inetpub\custerr\en-US
	4             inetpub\custerr
	4             inetpub\temp\appPools
	4             inetpub\history\CFGHISTORY_0000000003
	4             inetpub\temp\IIS Temporary Compressed Files\DefaultAppPool
	4             Thumbs.db:encryptable
	4             inetpub\temp\IIS Temporary Compressed Files
	4             inetpub\logs
	4             temp
	4             inetpub\wwwroot\Thumbs.db:encryptable
	4             inetpub\history\CFGHISTORY_0000000001
	4             inetpub\temp\appPools\DefaultAppPool
	5             Users\desktop.ini
	5             Program Files\desktop.ini
 
==========================================================
SSH Sessions
==========================================================
Format: # of occurence (Ascending), client ip, server ip, server port
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00003.pcap @ http://bit.ly/2maxlsD

	1             192.168.202.109  -------> 192.168.21.254   : 22/tcp
	1             192.168.202.87   -------> 192.168.28.203   : 22/tcp
	1             192.168.202.110  -------> 192.168.22.254   : 22/tcp
	1             192.168.202.96   -------> 192.168.25.202   : 22/tcp
	1             192.168.202.96   -------> 192.168.25.102   : 22/tcp
	3             192.168.202.112  -------> 192.168.23.101   : 22/tcp
	28            192.168.202.110  -------> 192.168.22.253   : 22/tcp
==========================================================
SSH Client_Strings
==========================================================
Format: # of occurence (Ascending), SSH client string
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00007.pcap @ http://bit.ly/2maxlsD

	1             
	4             SSH-2.0-OpenSSH_5.2
	6             SSH-1.5-Nmap-SSH1-Hostkey
	6             SSH-1.5-NmapNSE_1.0
	11            SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7
	12            SSH-2.0-Nmap-SSH2-Hostkey
	14            SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6
	30            SSH-2.0-OpenSSH_5.0
 
 
 
==========================================================
SSH Server_Strings
==========================================================
Format: # of occurence (Ascending), SSH server string
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00003.pcap @ http://bit.ly/2maxlsD


	2             SSH-1.99-Cisco-1.25
	3             SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3
	3             SSH-2.0-OpenSSH_5.8p1 Debian-7ubuntu1
	28            SSH-2.0-OpenSSH_4.5

==========================================================
SSH Auth_Success
==========================================================
Format: # of occurence (Ascending), SSH auth_success result (True/False)
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00008.pcap @ http://bit.ly/2maxlsD

	17            T
	73            F
 

==========================================================
SSL Servers_Names
==========================================================
Format: # of occurence (Ascending), SSL server name
</br>
Results from: Malware Traffic Analysis / 2016-09-20-traffic-analysis-exercise.pcap @ http://bit.ly/2lS8g4L



	2             .live.com
	4             .tor2web.org
	5             .microsoft.com

 
==========================================================
SSL Issuers
==========================================================
Format: # of occurence (Ascending), SSL issuer
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00003.pcap @ http://bit.ly/2maxlsD

 
	1             CN=3uat.zwdt0km.yeh.bsoj.umbg.net
	1             CN=Scorebot
	7             CN=192.168.22.254
	18            CN=192.168.25.254
	58            CN=SplunkCommonCA
	1180          CN=localhost.localdomain



==========================================================
SSL Validation_Status
==========================================================
Format: # of occurence (Ascending), SSL cert validation result
</br>
Results from: Malware Traffic Analysis / 2015-10-28-traffic-analysis-exercise.pcap @ http://bit.ly/2lS8g4L

	15            ok
	16            self signed certificate
 
 
==========================================================
RDP Sessions
==========================================================
Format: # of sessions (Ascending), client IP, server IP, server port 

	2             x.x.x.x    -------> y.y.y.y     : 3389/tcp
	5             x.x.x.x    -------> y.y.y.y     : 3389/tcp
	15            x.x.x.x    -------> y.y.y.y     : 3389/tcp

==========================================================
RDP Usernames
==========================================================
Format: # of occurence (Ascending), domain \ username

	2             Domain\Username
	20            Domain\Username


==========================================================
IRC session
==========================================================
Format: # of occurence (Ascending), client IP, server IP, server port
</br>
Results from: Honeynet Project / day1.pcap @ http://bit.ly/2mdPszy

	7             80.117.14.44     -------> 192.168.100.28   : 7000/tcp
	12            192.168.100.28   -------> 206.252.192.195  : 6667/tcp
	192           192.168.100.28   -------> 206.252.192.195  : 5555/tcp

==========================================================
IRC username
==========================================================
Format: # of occurence (Ascending), IRC username
</br>
Results from: Google CTF 2016 / irc.pcap @ http://bit.ly/2lO2lgc

	9             root-poppopret
 

==========================================================
IRC nick
==========================================================
Format: # of occurence (Ascending), IRC nickname
</br>
Results from: Google CTF 2016 / irc.pcap @ http://bit.ly/2lO2lgc

	3             Matir
	3             andrewg
	3             itsl0wk3y

 
==========================================================
FTP Sessions
==========================================================
Format: # of occurence (Ascending), client IP, Server IP, server port
</br>
Results from: Honeynet Project / day1.pcap @ http://bit.ly/2mdPszy

	4             192.168.100.28   -------> 192.18.99.122    : 21/tcp
	10            192.168.100.28   -------> 62.211.66.16     : 21/tcp

==========================================================
FTP Usernames
==========================================================
Format: # of occurence (Ascending), FTP username
</br>
Results from: Honeynet Project / day1.pcap @ http://bit.ly/2mdPszy


	4             anonymous
	10            bobzz

 
==========================================================
FTP Current_Working_Directories
==========================================================
Format: # of occurence (Ascending), FTP Current Working Directory
</br>
Results from: Honeynet Project / day1.pcap @ http://bit.ly/2mdPszy

	4             ./pub/patches
	10            .

==========================================================
FTP Commands
==========================================================
Format: # of occurence (Ascending), FTP command
</br>
Results from: Honeynet Project / day1.pcap @ http://bit.ly/2mdPszy

	5             PORT
	9             RETR

==========================================================
File MIME_Types
==========================================================
Format: # of occurence (Ascending), mime type, communication protocol
</br>
Results from: National CyberWatch Mid-Atlantic Collegiate Cyber Defense Competition / maccdc2012_00002.pcap @ http://bit.ly/2maxlsD

	1             application/x-shockwave-flash            -------> HTTP
	2             image/x-ms-bmp                           -------> HTTP
	2             application/x-dosexec                    -------> SMB
	8             application/xml                          -------> HTTP
	9             application/x-dosexec                    -------> HTTP
	13            text/x-php                               -------> HTTP
	14            image/x-icon                             -------> HTTP
	70            image/gif                                -------> HTTP
	95            image/png                                -------> HTTP
	250           application/pkix-cert                    -------> SSL
	315           text/json                                -------> HTTP
	765           text/plain                               -------> FTP_DATA
	1145          text/plain                               -------> HTTP
	2023          text/html                                -------> HTTP


