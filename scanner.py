import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from payloads import XSS_PAYLOADS, SQLI_PAYLOADS

HEADERS = {'User-Agent': 'WebAppVulnScanner/1.0'}


class SimpleCrawler:
    def __init__(self, base_url, max_pages=50):
        self.base = base_url
        self.visited = set()
        self.to_visit = [base_url]
        self.max_pages = max_pages

    def same_host(self, u):
        try:
            return urlparse(u).netloc == urlparse(self.base).netloc
        except Exception:
            return False

    def crawl(self):
        pages = []
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            try:
                resp = requests.get(url, headers=HEADERS, timeout=8)
                html = resp.text
            except Exception:
                continue
            self.visited.add(url)
            pages.append((url, html))
            soup = BeautifulSoup(html, 'lxml')
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href'])
                if self.same_host(link) and link not in self.visited:
                    self.to_visit.append(link)
        return pages


class Scanner:
    def __init__(self, base_url, max_pages=50):
        self.base = base_url
        self.crawler = SimpleCrawler(base_url, max_pages=max_pages)

    def find_forms(self, html):
        soup = BeautifulSoup(html, 'lxml')
        forms = []
        for form in soup.find_all('form'):
            f = {'action': form.get('action') or '', 'method': (form.get('method') or 'get').lower(), 'inputs': []}
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                itype = inp.get('type', 'text')
                f['inputs'].append({'name': name, 'type': itype})
            forms.append(f)
        return forms

    def scan(self):
        reports = []
        pages = self.crawler.crawl()
        for url, html in pages:
            # scan forms
            forms = self.find_forms(html)
            for form in forms:
                action = form['action'] or url
                action = urljoin(url, action)
                inputs = [i for i in form['inputs'] if i.get('name')]
                # XSS tests
                for payload in XSS_PAYLOADS:
                    data = {i['name']: payload for i in inputs}
                    try:
                        if form['method'] == 'post':
                            r = requests.post(action, data=data, headers=HEADERS, timeout=8)
                        else:
                            r = requests.get(action, params=data, headers=HEADERS, timeout=8)
                    except Exception:
                        continue
                    if payload in r.text:
                        reports.append({'url': action, 'type': 'Reflected XSS', 'payload': payload, 'evidence': 'payload reflected in response', 'severity': 'High'})
            # test query params
            for payload in XSS_PAYLOADS:
                test_url = url + (('&' if '?' in url else '?') + f'testparam={payload}')
                try:
                    r = requests.get(test_url, headers=HEADERS, timeout=8)
                except Exception:
                    continue
                if payload in r.text:
                    reports.append({'url': test_url, 'type': 'Reflected XSS', 'payload': payload, 'evidence': 'payload reflected in response', 'severity': 'High'})
            for payload in SQLI_PAYLOADS:
                test_url = url + (('&' if '?' in url else '?') + f'testparam={payload}')
                try:
                    r = requests.get(test_url, headers=HEADERS, timeout=8)
                except Exception:
                    continue
                txt = r.text.lower()
                for err in ['you have an error in your sql syntax', 'warning: mysql', 'unclosed quotation mark', 'sql syntax']:
                    if err in txt:
                        reports.append({'url': test_url, 'type': 'SQL Injection', 'payload': payload, 'evidence': err, 'severity': 'High'})
        return reports
