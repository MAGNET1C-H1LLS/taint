titles = request.json.get('titles', [])  # массив tainted
html_list = "<ul>"
for title in titles:  # title наследует taint
    html_list += "<li>" + title + "</li>"  # taint -> HTML sink
html_list += "</ul>"
return html_list
