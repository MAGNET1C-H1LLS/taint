import sqlite3

user_input = input("Enter ID: ")
query = f"SELECT * FROM users WHERE id = {user_input}"
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
cursor.execute(query)