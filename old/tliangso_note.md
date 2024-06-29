## Born2Root

Setup 2 VMs, 1 for Born2Root VM and 1 for Kali VM
Set both VM to connect to one another via NAT Network

Probing the connection using nmap on Born2Root ip result in:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-28 10:01 EDT
Nmap scan report for borntosec (10.0.2.15)
Host is up (0.00019s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```


