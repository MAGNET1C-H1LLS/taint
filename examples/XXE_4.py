# UNTRUSTED: request.get_data()
doc = request.get_data()
from lxml import etree
parser = etree.XMLParser(load_dtd=True, no_network=False)
tree = etree.fromstring(doc, parser=parser)  # should flag as XXE/SSRF risk

# UNTRUSTED: request.get_data()
doc = request.get_data()
from lxml import etree
tree = etree.fromstring(doc)
tree.xinclude()  # if doc was tainted -> potential remote includes -> flag