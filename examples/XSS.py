from flask import Flask, request, Response, render_template_string
app = Flask(__name__)

# Тест 1: Прямой вывод через Response
user_input = request.args.get('comment')
html = f"<div>{user_input}</div>"
response = Response(html)

# Тест 2: Шаблонизатор
template = f"<h1>{user_input}</h1>"
render_template_string(template)

# Тест 3: Установка куки
response.set_cookie('comment', user_input)

# Тест 4: Прямой возврат из Flask
@app.route('/')
def index():
    return user_input