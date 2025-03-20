const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session'); // Adicione esta linha
const app = express();
const port = process.env.PORT || 3000;

// Configuração do EJS e caminho explícito para "views"
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));

require('dotenv').config();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Conexão com o banco de dados SQLite
const db = new sqlite3.Database('./messages.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado ao banco de dados SQLite.');
});

// Criar tabelas
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        telefone TEXT NOT NULL,
        mensagem TEXT NOT NULL,
        data TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )`);

    const adminUser = 'admin';
    const adminPass = 'senha123';
    bcrypt.hash(adminPass, 10, (err, hash) => {
        if (err) return console.error(err);
        db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, [adminUser, hash]);
    });
});

// Middleware de autenticação
function isAuthenticated(req, res, next) {
    if (req.session.loggedIn) {
        return next();
    }
    res.redirect('/admin/login');
}

// Rota para a landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota para enviar mensagem
app.post('/submit', (req, res) => {
    const { nome, email, telefone, mensagem } = req.body;
    db.run(`INSERT INTO messages (nome, email, telefone, mensagem) VALUES (?, ?, ?, ?)`,
        [nome, email, telefone, mensagem], (err) => {
            if (err) return res.send('Erro ao enviar mensagem.');
            res.redirect('/#contato');
        });
});

// Rota para login
app.get('/admin/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) return res.render('login', { error: 'Usuário não encontrado.' });
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.loggedIn = true;
                res.redirect('/admin');
            } else {
                res.render('login', { error: 'Senha incorreta.' });
            }
        });
    });
});

// Rota do painel administrativo
app.get('/admin', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM messages ORDER BY data DESC`, [], (err, rows) => {
        if (err) return res.send('Erro ao carregar mensagens.');
        res.render('admin', { messages: rows });
    });
});

// Rota para deletar mensagem
app.post('/admin/delete/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.run(`DELETE FROM messages WHERE id = ?`, [id], (err) => {
        if (err) return res.send('Erro ao deletar mensagem.');
        res.redirect('/admin');
    });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});