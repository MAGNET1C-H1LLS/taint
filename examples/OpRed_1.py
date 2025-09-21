# UNTRUSTED: request.args.get('next')
next_url = request.args.get('next')
from flask import redirect
return redirect(next_url)  # taint -> redirect sink (нет проверки домена/схемы)
