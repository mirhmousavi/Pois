from pois import *


class TestUrl:
    def test_extract_domain_from_url(self):
        url = "http://wwww.github.com"
        Url(url).domain = "github.com"

    def test_extract_suffix_from_url(self):
        url = "http://wwww.github.com"
        Url(url).suffix = "com"
