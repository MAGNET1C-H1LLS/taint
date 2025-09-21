# UNTRUSTED: request.data
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)  # resolve_entities=True -> потенциально позволит XXE
doc = etree.fromstring(request.data, parser)
# чтение собранных узлов
