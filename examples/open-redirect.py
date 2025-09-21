from flask import redirect, request

url = request.args.get('url')
redirect(url)