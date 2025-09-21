# UNTRUSTED: raw xml
import xml.etree.ElementTree as ET
root = ET.fromstring(request.data)
# условный код, который находит <xi:include href="..."/> и делает requests.get(href)
for inc in root.findall('.//{http://www.w3.org/2001/XInclude}include'):
    href = inc.get('href')
    # taint -> network fetch
    resp = requests.get(href)  # taint -> SSRF sink
