# UNTRUSTED: request.data
from xml.dom.minidom import parseString
doc = parseString(request.data)  # DOM парсер может обрабатывать внешние ресурсы при некоторых конфигурациях
# дальнейшая логика
