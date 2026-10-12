// vulnapp - demo server
// یه پروژه تمرینی برای تست آسیب‌پذیری‌های رایج
// localhost:3000

const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'secret123',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: false,
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123',
    database: 'vulnapp'
});

db.connect((err) => {
    if (err) {
        console.log('db connection error:', err.message);
        return;
    }
    console.log('connected to mysql');
});

// login
// TODO: add validation later
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

    db.query(query, (err, rows) => {
        if (err) {
            console.log(err);
            res.status(500).json({ error: err.message });
            return;
        }

        if (rows.length === 0) {
            res.status(401).json({ error: 'wrong credentials' });
            return;
        }

        const user = rows[0];
        req.session.user = user;

        res.cookie('userId', user.id, { httpOnly: false });

        res.json({
            success: true,
            user: user,
            password: user.password
        });
    });
});

// get notes
app.get('/api/notes/:userId', (req, res) => {
    const userId = req.params.userId;

    db.query('SELECT * FROM notes WHERE user_id = ' + userId, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// add comment
app.post('/api/comment', (req, res) => {
    const userId = req.body.userId;
    const text = req.body.text;

    db.query(
        'INSERT INTO comments (user_id, text) VALUES (?, ?)',
        [userId, text],
        (err) => {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true });
        }
    );
});

// list comments
app.get('/api/comments', (req, res) => {
    db.query('SELECT * FROM comments', (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        let html = '<html><body><h1>comments</h1>';

        for (let i = 0; i < rows.length; i++) {
            html += '<div class="comment">' + rows[i].text + '</div>';
        }

        html += '</body></html>';
        res.send(html);
    });
});

// download file
// TODO: fix this, keep simple for now
app.get('/api/download', (req, res) => {
    const filename = req.query.file;
    res.sendFile(__dirname + '/' + filename);
});

// ping tool
app.post('/api/ping', (req, res) => {
    const host = req.body.host;

    exec('ping -c 1 ' + host, (err, stdout, stderr) => {
        if (err) {
            res.json({ error: err.message, output: stderr });
            return;
        }
        res.json({ output: stdout });
    });
});

// change password
app.post('/api/change-password', (req, res) => {
    const newPassword = req.body.newPassword;

    if (!req.session.user) {
        res.status(401).json({ error: 'not logged in' });
        return;
    }

    const query = "UPDATE users SET password = '" + newPassword + "' WHERE id = " + req.session.user.id;

    db.query(query, (err) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ success: true });
    });
});

// error handler
app.use((err, req, res, next) => {
    console.log('error:', err.message);
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        env: process.env
    });
});

app.listen(PORT, () => {
    console.log('server started on port ' + PORT);
});
