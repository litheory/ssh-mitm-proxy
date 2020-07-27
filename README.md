# ssh-proxy

## Overview

> It’s very common for hackers to use SSH in order to stay under the radar of security products.
>
> SSH can be exploited for hacking in many ways:
>
> 1. SSH is a very common and is usually accepted by most security devices.
> 2. SSH Tunneling allows an attacker to transfer any traffic he desires over the standard SSH connection – [Hackers Are Using SSH Tunnels to Send Spam](http://www.rackaid.com/blog/spam-ssh-tunnel/)
> 3. SSH doesn’t have certificates that the Security Devices could compare against an Certificate Authority to authenticate the server
>
> The main issue with blocking “malicious” SSH connections is that it’s close to impossible to tell the difference between malicious and non-malicious SSH connections without decrypting the traffic. SSH represents a potential way to **bypass** **security** by creating connections the security device is not able to fully inspect.
>
> To mitigate this threat, a few major security vendors recently published statements that they are mitigating malicious-SSH usage by creating a feature that enables the ability to intercept and decrypt SSH traffic. Following our research we noticed that current available SSH decryption solutions are exposing organizations to MiTM attacks.

`ssh-proxy` is an intercepting (mitm) proxy server for security audits.

`ssh-proxy` allows an auditor to intercept SSH connections. Based on libssh, it act as a proxy between the victim SSH CLIENT and their intended SSH SERVER, the proxy server side intercept all plaintext passwords and sessions, and forwarded these to intended SERVER by client side.

Of course, the victim's SSH CLIENT will complain that the server's key has changed. But because 99.99999% of the time this is caused by a legitimate action (OS re-install, configuration change, etc), many/most users will disregard the warning and continue on. 

The proxy server side use approach of “One to rule them all” (A single Fingerprint that controls the entire session flow),  while client side will accept any SERVER’s key. Unfortunately this method doesn’t have any MiTM countermeasure. See more: [Lies, Damn Lies, and Inspecting SSH Traffic Securely](http://phoneboy.org/2015/07/29/lies-damn-lies-and-inspecting-ssh-traffic-securely/)

## Change Log

- v1.0: July 22, 2020: Initial revision. Support ssh interactive shell session.

>  **Do not use this library in production environments! This tool is only for security audits!**

## To Do

- Add SCP support v2.0
- Add SFTP support v2.0
- Add direct-tcpip port fowarding support v3.0
- Add forwarded-tcpip port forwarding support v3.0
- Add X11 support v4.0

## Initial Setup

**Download**

```
https://github.com/p0st3r/ssh-proxy.git
```

**Dependency**

```
apt-get install libssh-dev
```

**Compile**

```
gcc *.c -o ssh-proxy -lssh -lpthread
```

## Start Proxy Server

### usage

Start the server:

```
./ssh-proxy --rhost [remote host] --rport [remote port] --lport [listen port] [Any redundancy char]
```

**NOTE** the command must follow a redundancy character or string, because of a \<argp.h\> bug.

such as:

```
./ssh-proxy --rhost 10.100.1.31 1234
```

Connect to server:

```
ssh -p 2222 user@server
```

### help

```
Usage: sshd_test [OPTION...]
ssh-proxy --  an intercepting (mitm) proxy server for security audits.
  -t, --rhost=HOST           Set the proxy destination remote host
  -p, --rport=PORT           Set the proxy destination remote port.
                             defualt 22
  -l, --lport=PORT           Set the local port to bind.
                             default 2222
  -v, --verbosity=VERBOSE    Produce verbose output [0-4].	
                             default 0  
  -k, --hostkey=FILE         Set a host key. Can be used multiple times.
  				                   default /etc/ssh/ssh_host_ed25519_key
  -d, --dsakey=FILE          Set the dsa key. 	
                             default /etc/ssh/ssh_dsa_key
  -e, --ecdsakey=FILE        Set the ecdsa key.	
                             default /etc/ssh/ssh_ecdsa_key
  -r, --rsakey=FILE          Set the rsa key.	
                             default /etc/ssh/ssh_rsa_key

  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

## SSH MITM Attacks

SSH uses trust on first use. This means, that you have to accept the fingerprint if it is not known.

```
$ ssh -p 10022 hugo@localhost
The authenticity of host '[localhost]:10022 ([127.0.0.1]:10022)' can't be established.
RSA key fingerprint is SHA256:GIAALZgy8Z86Sezld13ZM74HGbE9HbWjG6T9nzja/D8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:10022' (RSA) to the list of known hosts.
```

If a server fingerprint is known, ssh warns the user, that the host identification has changed.

```
$ ssh -p 10022 remoteuser@localhost
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
SHA256:GIAALZgy8Z86Sezld13ZM74HGbE9HbWjG6T9nzja/D8.
Please contact your system administrator.
Add correct host key in /home/user/.ssh/known_hosts to get rid of this message.
Offending RSA key in /home/user/.ssh/known_hosts:22
  remove with:
  ssh-keygen -f "/home/user/.ssh/known_hosts" -R "[localhost]:10022"
RSA host key for [localhost]:10022 has changed and you have requested strict checking.
Host key verification failed.
```

**If the victim accepts the (new) fingerprint, then the session can be intercepted.**

### Use-Case: Honey Pot

When ssh proxy server is used as a honey pot, attackers will accept the fingerprint, because he wants to attack this machine. An attacker also does not know if the fingerprint is correct and if the key has changed, perhaps it the server was reinstalled and a new keypair was generated.

### User-Case: Security Audit

Intercepting ssh during security audits is useful to understand, how an application works.

For example, if you have an application, which connects to you local router via ssh, to configure the device, you can intercept those connections, if the application does not know the fingerprint and accept it on first use.

If the application knows the fingerprint, then the same host key is used on every device. In this case, you have a good chance to extract the host key from a firmware updated and use it to trick the application.

## See also

- [jtesta](https://github.com/jtesta)/**[ssh-mitm](https://github.com/jtesta/ssh-mitm)**
- [manfred-kaiser](https://github.com/manfred-kaiser)/**[ssh-proxy-server](https://github.com/manfred-kaiser/ssh-proxy-server)**
- [Palo Alto]()/**[SSH Proxy](https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/decryption/decryption-concepts/ssh-proxy.html)**
- [Checkpoint]()/**[SSH Decryption Opens Door to Very Old Security Vectors](https://blog.checkpoint.com/2015/08/12/ssh-decryption-opens-door-to-very-old-security-vectors/)**

