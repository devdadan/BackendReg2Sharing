const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

const secretKey = '202319970717';

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'dadan199717',
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
app.get('/api/programrelease', (req, res) => {
    db.query("SELECT a.id, a.nama_program, a.versi_program, IFNULL(b.tgl_rilis,'') AS tgl_rilis, IFNULL(b.perubahan, '') AS perubahan FROM table_program a LEFT JOIN table_simulasi b ON a.`nama_program`=b.`nama_program` AND a.`versi_program`=b.`versi` order by tgl_rilis DESC", (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }
        try {
            const formattedResults = results.map(result => ({
                id: result.id,
                nama_program: result.nama_program,
                versi_program: result.versi_program,
                tgl_rilis: result.tgl_rilis,
                perubahan: isJSON(result.perubahan) ? JSON.parse(result.perubahan) : null,
            }));

            res.json(formattedResults);
        } catch (error) {
            console.error(error);
            return res.status(500).json({ message: 'Internal Server Error', error: error.message });
        }
        
    });
});
app.get('/api/programsimulasi', (req, res) => {
    db.query("SELECT id,tgl_terima,nama_program,versi,perubahan FROM table_simulasi WHERE `status`='simulasi';", (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Internal Server Error', error: err.message });
        }
        try {
            const formattedResults = results.map(result => ({
                id: result.id,
                tgl_terima : result.tgl_terima,
                nama_program: result.nama_program,
                versi_program: result.versi,
                perubahan: isJSON(result.perubahan) ? JSON.parse(result.perubahan) : null,
            }));

            res.json(formattedResults);
        } catch (error) {
            console.error(error);
            return res.status(500).json({ message: 'Internal Server Error', error: error.message });
        }
        
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

function isJSON(text) {
    try {
        JSON.parse(text);
        return true;
    } catch (error) {
        return false;
    }
}
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
