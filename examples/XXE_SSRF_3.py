# UNTRUSTED: raw xml that contains xi:include href="http://internal/..."
from lxml import etree
doc = etree.fromstring(request.data)
# вызов xinclude может инициировать HTTP fetch для href
doc.xinclude()  # если xinclude обрабатывает внешние href -> сетевой запросы
