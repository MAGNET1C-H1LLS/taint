# UNTRUSTED: request.form.get('name')
name = request.form.get('name')
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))  # parameterized -> sanitizer sufficient for SQL
