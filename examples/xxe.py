from lxml import etree

xml_data = input("Enter XML: ")
root = etree.parse(xml_data)