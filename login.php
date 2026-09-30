<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Portal - Secure Access</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --accent-blue: #0284c7;
            --accent-red: #dc2626;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            color: var(--text-main);
        }
        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            width: 380px;
        }
        .portal-title {
            font-size: 20px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 25px;
            color: var(--text-main);
            letter-spacing: 0.5px;
        }
        .form-group {
            margin-bottom: 18px;
        }
        label {
            display: block;
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px 14px;
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: white;
            font-size: 13px;
            box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        .btn-login {
            width: 100%;
            padding: 11px;
            background: var(--accent-blue);
            color: white;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 10px;
        }
        .btn-login:hover {
            background: #0369a1;
        }
        .error-msg {
            background: rgba(220, 38, 38, 0.15);
            border: 1px solid var(--accent-red);
            color: #fca5a5;
            padding: 10px;
            border-radius: 4px;
            font-size: 12px;
            margin-bottom: 15px;
            text-align: center;
        }
        .footer-note {
            text-align: center;
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 20px;
        }
    </style>
</head>
<body>

    <div class="login-card">
        <div class="portal-title">Enterprise Portal</div>
        
        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}

        <form method="POST" action="">
            {% csrf_token %}
            <div class="form-group">
                <label for="user">Username / Email</label>
                <input type="text" id="user" name="user" required autocomplete="off">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-login">Secure Login</button>
        </form>

        <div class="footer-note">Restricted Access • Monitored Environment</div>
    </div>

</body>
</html>