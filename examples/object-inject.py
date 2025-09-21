import pickle
import yaml
import json
import marshal
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString
import lxml.etree

# Тест 1: pickle
data = input("Enter pickle data: ")
obj = pickle.loads(data.encode())

# Тест 2: yaml
yaml_data = input("Enter YAML data: ")
obj = yaml.load(yaml_data)

# Тест 3: json
json_data = input("Enter JSON data: ")
obj = json.loads(json_data)

# Тест 4: marshal
marshal_data = input("Enter marshal data: ")
obj = marshal.loads(marshal_data.encode())

# Тест 5: XML
xml_data = input("Enter XML data: ")
root = ET.fromstring(xml_data)

# Тест 6: lxml
lxml_data = input("Enter lxml data: ")
root = lxml.etree.fromstring(lxml_data)

# Тест 7: minidom
minidom_data = input("Enter minidom data: ")
doc = parseString(minidom_data)