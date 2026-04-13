from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Create vulnerable database
conn = sqlite3.connect('test.db')
conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, password TEXT)')
conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
conn.execute("INSERT INTO users VALUES (2, 'user', 'password')")
conn.commit()
conn.close()

HTML_FORM = '''
<!DOCTYPE html>
<html>
<body>
    <h2>Vulnerable Test App (SQL Injection Demo)</h2>
    <form method="GET">
        <label>User ID: </label>
        <input type="text" name="id" value="{{ request.args.get('id', '') }}">
        <input type="submit" value="Search">
    </form>
    <hr>
    <pre>{{ result }}</pre>
</body>
</html>
'''

@app.route('/')
def index():
    user_id = request.args.get('id', '')
    result = ""
    
    if user_id:
        try:
            # VULNERABLE CODE - DO NOT USE IN PRODUCTION
            conn = sqlite3.connect('test.db')
            cursor = conn.cursor()
            query = f"SELECT * FROM users WHERE id = {user_id}"
            result += f"Query: {query}\n\n"
            cursor.execute(query)
            rows = cursor.fetchall()
            if rows:
                for row in rows:
                    result += f"Found: ID={row[0]}, Name={row[1]}, Password={row[2]}\n"
            else:
                result += "No results found"
            conn.close()
        except Exception as e:
            result += f"Error: {e}"
    
    return render_template_string(HTML_FORM, result=result, request=request)

if __name__ == '__main__':
    print("\n🔥 Vulnerable Test Server Running!")
    print("📡 Access at: http://localhost:5000/?id=1")
    print("🎯 Test SQL injection: http://localhost:5000/?id=1' OR '1'='1")
    print("\n⚠️  ETHICAL USE ONLY - This is for learning!\n")
    app.run(debug=True, host='0.0.0.0', port=5000)