# UNTRUSTED: request.form.get('note')
note = request.form.get('note')
with open("/var/log/app.log", "a") as f:
    f.write("NOTE: " + note + "\n")  # taint -> log sink (возможна инъекция строк/манипуляция логов)
