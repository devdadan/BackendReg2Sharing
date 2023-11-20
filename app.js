const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

const secretKey = '202319970717';

const db = mysql.createConnection({
    host: '192.168.190.100',
    user: 'root',
    password: '15032012',
    database: 'siedp'
});

app.use(cors());
app.use(express.json());

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM userlogin WHERE nik=? AND AES_DECRYPT(UNHEX(Pass_encrypt),"wkwk")=?', [username, password], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }

        if (results.length > 0) {
            const user = { username: results[0].username, id: results[0].id,level:results[0].level };
            const token = jwt.sign(user, secretKey, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Authentication failed', error: 'Invalid username or password' });
        }
    });
});

app.get('/secure', verifyToken, (req, res) => {
    const userId = req.user.id;
    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }

        if (results.length > 0) {
            res.json({ message: 'Secure Area', user: results[0] });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    });
});
app.get('/api/dataprefix', (req, res) => {
    db.query('SELECT * FROM prefix', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }

        res.json(results);
    });
});

app.get('/api/cobermasalah', (req, res) => {
    db.query('SELECT * FROM cobermasalah_tmp ORDER BY tanggalco DESC', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }

        res.json(results);
    });
});

function verifyToken(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized', error: 'Token not provided' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            console.error(err);
            return res.status(403).json({ message: 'Forbidden', error: 'Invalid token' });
        }

        req.user = decoded;
        next();
    });
}

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
