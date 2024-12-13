# winrmexec
Impacket-based WinRM client with support for NTLM and Kerberos authentication over HTTP and HTTPS in the spirit of `smbexec.py` and `psexec.py`. You can run a single command with `-X 'whoami /all'`, or use the "shell" mode to issue multiple commands. It depends on `impacket`, `requests`, `pycryptodome`, `xmltodict`, and optionally `prompt_toolkit` python packages. If `prompt_toolkit` is not installed on your system, it defaults to the built-in `readline` module for.

## Examples
In the following examples impacket's "target" format will be used: `[[domain/]username[:password]@]<target>`.

### NTLM:
```bash
$ winrmexec.py 'box.htb/username:password@dc.box.htb'
$ winrmexec.py 'username:password@dc.box.htb'
$ winrmexec.py -hashes 'LM:NT' 'username@dc.box.htb'
$ winrmexec.py -hashes ':NT' 'username@dc.box.htb'
```
If `password` or `-hashes` are not specified, it will prompt for password:
```bash
$ winrmexec.py username@dc.box.htb
Password:
```

If `-target-ip` is specified, `target` will be ignored (still needs `@` after `username[:password]`)
```bash
$ winrmexec.py -target-ip '10.10.11.xx' 'username:password@whatever'
$ winrmexec.py -target-ip '10.10.11.xx' 'username:password@'
```

If `-target-ip` is not specified, then `-target-ip=target`. If `-ssl` is specified, it will use 5986 port and https:
```bash
$ winrmexec.py -ssl 'username:password@dc01.box.htb'
```
If `-port` is specified, it will use that instead of 5985. If `-ssl` is also specified it will use https:
```bash
$ winrmexec.py -ssl -port 8443 'username:password@dc01.box.htb'
```
If `-url` is specified, `target`, `-target-ip` and `-port` will be ignored:
```bash
$ winrmexec.py -url 'http://dc.box.htb:8888/endpoint' 'username:password@whatever'
```
If `-url` is not specified it will be constructed as `http(s)://target_ip:port/wsman`

### Kerberos:
```bash
$ winrmexec.py -k 'box.htb/username:password@dc.box.htb'
$ winrmexec.py -k -hashes 'LM:NT' 'box.htb/username@dc.box.htb'
$ winrmexec.py -k -aesKey 'AESHEX' 'box.htb/username@dc.box.htb'
```

If `KRB5CCACHE` is set as env variable, it will use `domain` and `username` from there:
```bash
$ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass 'dc.box.htb'
```
It doesn't hurt if you also specify `domain/username`, but they will be ignored:
```bash
$ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass 'box.htb/username@dc.box.htb'
```
If `target` does not resolve to an ip, you have to specify `-target-ip`:
```bash
$ winrmexec.py -k -no-pass -target-ip '10.10.11.xx' 'box.htb/username:password@DC'
$ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass -target-ip '10.10.11.xx' DC
```
For Kerbros it is important that `target` is a host or FQDN, as it will be used to construct SPN as `HTTP/{target}@{domain}`. Or you can specify `-spn` yourself, in which case `target` will be ignored (or used only as `-target-ip`):
```bash
$ winrmexec.py -k -spn 'http/dc' 'box.htb/username:password@dc.box.htb'
$ winrmexec.py -k -target-ip '10.10.11.xx' -spn 'http/dc' box.htb/username:password@whatever
$ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass -target-ip '10.10.11.xx' -spn 'http/dc' 'whatever'
```
If you have a TGS for SPN other than HTTP (for example CIFS) it still works (at least from what i tried). If you have a TGT, then it will request TGS for `HTTP/target@domain` (or your custom `-spn`)

If `-dc-ip` is not specified then `-dc-ip=domain`. For `-url` / `-port` / `-ssl` same rules apply as for NTLM.

### Basic Auth:
Not likelyto be enabled, but if it is same rules as for NTLM (but no `-hashes`)
```bash
winrmexec.py -basic username:password@dc.box.htb
winrmexec.py -basic -target-ip '10.10.11.xx' 'username:password@whatever'
winrmexec.py -basic -target-ip '10.10.11.xx' -ssl 'username:password@whatever'
winrmexec.py -basic -url 'http://10.10.11.xx/endpoint' 'username:password@whatever'
```

