# UNTRUSTED: xml payload with external entity referencing http://internal/service
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)  # позволит парсеру выполнить HTTP-запрос при разрешении сущности
doc = etree.fromstring(request.data, parser)
