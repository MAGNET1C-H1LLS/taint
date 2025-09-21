# UNTRUSTED: request.data (XML)
import xml.etree.ElementTree as ET
xml = request.data
root = ET.fromstring(xml)  # taint -> XML parser (may allow external entities depending on environment)
# дальнейшая обработка root...
