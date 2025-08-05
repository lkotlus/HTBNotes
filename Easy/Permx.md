## Enumeration
### Nmap
- Let's see what we've got...
```a
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-19 14:07 EDT  
Nmap scan report for permx.htb (10.10.11.23)  
Host is up (0.018s latency).  
Not shown: 998 closed tcp ports (reset)  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)  
80/tcp open  http    Apache httpd 2.4.52  
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```
- Pretty standard. I'm too smart to try that ssh port, and that Apache version seems secure.
	- After checking edb, I can exploit if I find a Lua script.
- Other than that, I don't see much of anything.

### Web crawl
- Let's look around, shall we?
- The contact form is the only thing of interest that I can find by hand.
	- It isn't even functional, it just pretends to refresh the page.
- Let's give Burp a shot.
	- Hasn't found anything that interesting.

### Subdomains
- Let's look for some subdomains, I found a neat tool called `ffuf` that I'd like to try out.
- Output of `ffuf -u https://permx.htb -H Host:FUZZ.permx.htb -w Nerd/wordlists/SecLists/Discovery/DNS/subdomains-top-whatever -fw 18` shows that there's a `www` subdomain and a `lms` subdomain.
- The lms subdomain seems promising!

### New subdomain (`lms`)
- We've got something that looks pretty vulnerable!
- Administrator information
	- Full name: Davis Miller
	- Email: admin@permx.htb
- The site is using something called Chamilo.
	- It's an LMS (learning management system)
	- Version is unknown, but it has previous RCE vulnerabilities.
- Let's poke around this site a little bit.
- Source code shows that it should be version 1.x, that's promising.

## Foothold!
- So I'm in with a php reverse shell.
- Any upload is allowed on a certain endpoint, pretty crazy exploit.
- So I need to figure out how to get into a user account. It would be cool if I could find where the password hashes are stored for Chamilo, because I know for a fact that they are using SHA1 and MD5 for that. If I get some hashes dumped I'm at least inside the full web application.
- I see a config file: `app/config/configuration.php`
- Inside, we get some credentials for a database:
```a
// Database connection settings.  
$_configuration['db_host'] = 'localhost';  
$_configuration['db_port'] = '3306';  
$_configuration['main_database'] = 'chamilo';  
$_configuration['db_user'] = 'chamilo';  
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';  
// Enable access to database management for platform admins.  
$_configuration['db_manager_enabled'] = false;
```
- I have a user and a password, I'd imagine that it only allows inbound connectiosn though.
- So apparently getting into the database and cracking hashes is a waste of time. Password for the `mtz` user is the same as `db_password`. Heck.

## User!
- Aight, so we in.
- I can ssh now, so I'm glad to have a real shell.
- This user has sudo permissions to run a single bash script as root.
	- It changes the permissions of any file within my home directory.
	- It checks for `..` in the path.
	- It doesn't detect symlinks!
	- It doesn't seem to be changing perms at all.