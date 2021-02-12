# Pois
Whois lookup behind proxy using Python


## Why use Pois over other libraries?

So why use Pois over robust libraries like [pythonwhois](https://github.com/joepie91/python-whois), [pywhois](https://bitbucket.org/richardpenman/pywhois)...

1. It supports idn domains.

2. It supports over 1449 tlds (thanks to [dnpedia](https://dnpedia.com/tlds/)) and if it didn't find any whois server for a specific brand new tld
 it query `whois.iana.org` to get tld whois server (`tlds.json` file will be updated when new whois servers fetched).

3. It accepts http and socks proxies, thank to `pysocks`.

4. It accepts user defined whois server to query desired domain.

5. It accepts a timeout for whois operation, some whois servers time out after user quota exceeded.

6. It parses result and if it finds a Registrar whois server, re-whois that server to get complete whois (thick whois).

7. Pois uses `chardet` library to detect encoding of whois and give you correctly utf-8 decoded result.


## Getting started

Install dependencies

```
pip install -r requirements.txt
```

Copy `pois` folder anywhere you want then import it.

First create a `Pois` object

```python

p = Pois()

```

You can set a timeout for whois operation by passing `timeout` argument, timeout must be an integer <br>
to set proxy just pass `proxy_info` dict with these arguments<br>

- `proxy_type`: must be `http`,`socks4` or `socks5`<br>
- `addr`: server ip or address<br>
- `username`: proxy username if specified<br>
- `password`: proxy password if specified<br>
- `port`: proxy port in integer<br>

to fetch whois of  domain just call `fetch` method, this method take two arguments, `domain` and `whois_server`
- `domain` is the domain that you want to fetch whois of<br>
- `whois_server` is the whois server that you want to query the domain on that server, if set to None Pois will use
the authentic whois server for that domain tld<br>
see `tests` for more examples


```python

from pois import *

# without proxy
try:
    p = Pois(timeout=10)
    result = p.fetch(domain='github.com', whois_server='whois.verisign-grs.com')
    # or
    result = p.fetch(domain='github.com',)
except Exception as err:
    print(str(err))
    
    
# with proxy
try:
    proxy_info = {'proxy_type':'http','addr':'localhost', 'port':8118}
    p = Pois(timeout=10, proxy_info=proxy_info)
    result = p.fetch(domain='github.com', whois_server=None,)
except Exception as err:
    print(str(err))
    
    
```

- In many cases, when we query registrar whois server, we get full information but sometimes the registry whois sever gives us full information like 'php.guru', so we return both results



## Exceptions


```
TldsFileError, BadDomainError, NoWhoisServerFoundError, SocketTimeoutError, SocketError, SocketBadProxyError

```
