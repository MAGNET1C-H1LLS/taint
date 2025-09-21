# UNTRUSTED: request.args.get('q')
import html
q = request.args.get('q')
q_html = html.escape(q)  # HTML sanitizer, но далее используется в SQL
cursor.execute("SELECT * FROM t WHERE c = '%s'" % q_html)  # taint -> SQL sink still vulnerable
