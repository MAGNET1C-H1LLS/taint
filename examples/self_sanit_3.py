# UNTRUSTED: request.values.get('text')
import re
def strip_tags(s):
    return re.sub(r"<[^>]*>", "", s)  # убирает теги, но не экранирует для SQL
t = strip_tags(request.values.get('text'))
cursor.execute("INSERT INTO notes(text) VALUES ('%s')" % t)  # taint -> SQL sink
