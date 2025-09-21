# UNTRUSTED: raw xml
import xml.sax
parser = xml.sax.make_parser()
# при использовании стандартного EntityResolver парсер может обратиться по URL, указанному во внешней сущности
xml.sax.parseString(request.data, xml.sax.handler.ContentHandler())
