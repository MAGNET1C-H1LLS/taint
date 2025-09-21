# UNTRUSTED: request.args.get('next_page')
next_page = request.args.get('next_page')
from flask import redirect

# прямой редирект через tainted URL
return redirect(next_page)  # taint -> redirect sink (нет проверки домена/схемы)
