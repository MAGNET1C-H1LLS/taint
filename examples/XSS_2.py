# UNTRUSTED: request.form.get('bio')
bio = request.form.get('bio')
from flask import render_template_string
return render_template_string("<div>{{ bio|safe }}</div>", bio=bio)  # taint -> HTML sink via safe
