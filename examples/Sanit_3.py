# UNTRUSTED: request.form.get('val')
import html
val = request.form.get('val')
val_escaped = html.escape(val)  # для HTML, но используем в JS-строке
return f"<script>var v = '{val_escaped}'; document.write(v);</script>"  # контекст mismatch -> XSS возможен
