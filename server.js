require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Log para verificar o SESSION_SECRET
console.log('SESSION_SECRET:', process.env.SESSION_SECRET || 'usando fallback');

// Configuração do Express
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
    secret: process.env.SESSION_SECRET || 'fallback-secret-123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./messages.db', (err) => {
    if (err) console.error('Erro ao conectar ao banco:', err.message);
    console.log('Conectado ao banco de dados SQLite.');
});

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
    const adminPass = '489121'; // Senha corrigida
    bcrypt.hash(adminPass, 10, (err, hash) => {
        if (err) return console.error('Erro ao criar hash:', err);
        db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, [adminUser, hash], (err) => {
            if (err) console.error('Erro ao inserir admin:', err);
            else console.log('Usuário admin criado ou já existe.');
        });
    });
});

function isAuthenticated(req, res, next) {
    console.log('Verificando autenticação - loggedIn:', req.session.loggedIn, 'Session ID:', req.sessionID);
    if (req.session.loggedIn) return next();
    res.redirect('/admin/login');
}

app.get('/', (req, res) => {
    console.log('Acessando raiz');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/submit', (req, res) => {
    const { nome, email, telefone, mensagem } = req.body;
    console.log('Recebendo mensagem:', { nome, email, telefone, mensagem });
    db.run(`INSERT INTO messages (nome, email, telefone, mensagem) VALUES (?, ?, ?, ?)`,
        [nome, email, telefone, mensagem], (err) => {
            if (err) {
                console.error('Erro ao salvar mensagem:', err);
                return res.send('Erro ao enviar mensagem.');
            }
            res.redirect('/#contato');
        });
});

app.get('/admin/login', (req, res) => {
    console.log('Acessando página de login');
    res.render('login', { error: null });
});

app.post('/admin/login', (req, res) => {
    console.log('Recebendo POST /admin/login');
    const { username, password } = req.body;
    console.log('Tentativa de login:', { username });
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            console.error('Erro no banco de dados:', err);
            return res.status(500).render('login', { error: 'Erro interno.' });
        }
        if (!user) {
            console.log('Usuário não encontrado:', username);
            return res.render('login', { error: 'Usuário não encontrado.' });
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).render('login', { error: 'Erro interno.' });
            }
            if (result) {
                console.log('Login bem-sucedido:', username);
                req.session.loggedIn = true;
                req.session.save((err) => {
                    if (err) {
                        console.error('Erro ao salvar sessão:', err);
                        return res.status(500).render('login', { error: 'Erro ao salvar sessão.' });
                    }
                    console.log('Sessão após login - loggedIn:', req.session.loggedIn, 'Session ID:', req.sessionID);
                    res.redirect('/admin');
                });
            } else {
                console.log('Senha incorreta para:', username);
                return res.render('login', { error: 'Senha incorreta.' });
            }
        });
    });
});

app.get('/admin', isAuthenticated, (req, res) => {
    console.log('Acessando admin');
    db.all(`SELECT * FROM messages ORDER BY data DESC`, [], (err, rows) => {
        if (err) {
            console.error('Erro ao carregar mensagens:', err);
            return res.send('Erro ao carregar mensagens.');
        }
        res.render('admin', { messages: rows });
    });
});

app.post('/admin/delete/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    console.log('Deletando mensagem ID:', id);
    db.run(`DELETE FROM messages WHERE id = ?`, [id], (err) => {
        if (err) {
            console.error('Erro ao deletar mensagem:', err);
            return res.send('Erro ao deletar mensagem.');
        }
        res.redirect('/admin');
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});