# UNTRUSTED: request.data may contain <xi:include href="http://internal/..."/>
from lxml import etree
parser = etree.XMLParser(load_dtd=False, resolve_entities=False)
doc = etree.fromstring(request.data, parser)
doc.xinclude()  # xinclude может всё равно выполнить HTTP-запросы по href
