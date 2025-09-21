# UNTRUSTED: raw xml
from xml.dom.minidom import parseString
doc = parseString(request.data)
# если код затем вручную обработает <xi:include> и сделает fetch(href), то будет SSRF/XXE через XInclude
# пример показывает, что наличие запрета DOCTYPE не исключает fetch'и по XInclude
