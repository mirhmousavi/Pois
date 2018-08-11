# Pois
Whois client for Python with Proxy


## Why use Pois over other libraries?


so why use Pois over robust libraries like [pythonwhois](https://github.com/joepie91/python-whois), [pywhois](https://bitbucket.org/richardpenman/pywhois)...


1. Pois uses a complete list of whois servers for all available tlds  thanks to [dnpedia](https://dnpedia.com/tlds/) and if it didn't find any whois server for a specific brand new tld
 it query `whois.iana.org` to get tld whois server (`tlds.json` file will be updated when new whois servers fetched)

2. Pois accept http and socks proxies, thank to `pysocks`

3. Pois accepts user defined whois server to query desired domain

4. Pois accepts a timeout for whois operation, some whois servers time out after user quota exceeded

5. Pois parses result and if it finds a Registrar whois server, re-whois that server to get complete whois (thick whois)

6. Pois uses fantastic `chardet` library to detect encoding of whois and give you correctly utf-8 decoded result. for example if you use other libraries
to get whois of `cloudpbx.com.tr` you see REPLACEMENT_CHARACTER inside result that's because they just decode result to utf-8 and replace
undecodable characters.


## Getting started

Install `pysocks` and `tlddextract` <br>
```
pip install pysocks tldextract chardet
```

copy `pois` folder anywhere you want then import it.
first create a `Pois` object

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


## Exceptions


```
TldsFileError, BadDomainError, NoWhoisServerFoundError, SocketTimeoutError, SocketError, SocketBadProxyError

```





