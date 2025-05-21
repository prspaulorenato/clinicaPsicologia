require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const Knex = require('knex');
const connectSessionKnex = require('connect-session-knex')(session);
const helmet = require('helmet');
const csurf = require('csurf');
const path = require('path');
const app = express();
const port = process.env.PORT || 8080;

const knex = Knex({
    client: 'sqlite3',
    connection: {
        filename: './sessions.db'
    },
    useNullAsDefault: true
});

const store = new connectSessionKnex({
    knex: knex,
    tablename: 'sessions'
});

console.log('SESSION_SECRET:', process.env.SESSION_SECRET || 'usando fallback');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    console.log('Cookies em todas as requisições:', req.headers.cookie);
    const originalSetHeader = res.setHeader;
    res.setHeader = function (name, value) {
        if (name.toLowerCase() === 'set-cookie') {
            console.log('Set-Cookie Header:', value);
        }
        return originalSetHeader.call(this, name, value);
    };
    next();
});

app.use(session({
    store: store,
    secret: process.env.SESSION_SECRET || 'fallback-secret-123',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
        path: '/'
    },
    name: 'sessionId'
}));

const csrfProtection = csurf({ cookie: false });

const db = new sqlite3.Database('./messages.db', (err) => {
    if (err) console.error('Erro ao conectar ao banco:', err.message);
    console.log('Conectado ao banco de dados SQLite (messages.db).');
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
    db.get(`SELECT * FROM users WHERE username = ?`, ['admin'], (err, user) => {
        if (err) return console.error('Erro ao buscar admin:', err);
        if (!user) {
            const adminUser = 'admin';
            const adminPass = 'Pauleta1984$$';
            bcrypt.hash(adminPass, 10, (err, hash) => {
                if (err) return console.error('Erro ao criar hash:', err);
                db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [adminUser, hash], (err) => {
                    if (err) console.error('Erro ao inserir admin:', err);
                    else console.log('Usuário admin criado com sucesso.');
                });
            });
        }
    });
});

function isAuthenticated(req, res, next) {
    console.log('Verificando autenticação - loggedIn:', req.session.loggedIn, 'Session ID:', req.sessionID, 'Cookies:', req.headers.cookie);
    if (req.session.loggedIn) return next();
    res.redirect('/admin/login');
}

app.get('/', csrfProtection, (req, res) => {
    console.log('Acessando raiz');
    res.render('index', { csrfToken: req.csrfToken() });
});

app.post('/submit', csrfProtection, (req, res) => {
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

app.get('/admin/login', csrfProtection, (req, res) => {
    console.log('Acessando página de login');
    res.render('login', { error: null, csrfToken: req.csrfToken() });
});

app.post('/admin/login', csrfProtection, (req, res) => {
    console.log('Recebendo POST /admin/login');
    const { username, password } = req.body;
    console.log('Tentativa de login:', { username });
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            console.error('Erro no banco de dados:', err);
            return res.status(500).render('login', { error: 'Erro interno.', csrfToken: req.csrfToken() });
        }
        if (!user) {
            console.log('Usuário não encontrado:', username);
            return res.render('login', { error: 'Usuário não encontrado.', csrfToken: req.csrfToken() });
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).render('login', { error: 'Erro interno.', csrfToken: req.csrfToken() });
            }
            if (result) {
                console.log('Login bem-sucedido:', username);
                req.session.loggedIn = true;
                req.session.save((err) => {
                    if (err) {
                        console.error('Erro ao salvar sessão:', err);
                        return res.status(500).render('login', { error: 'Erro ao salvar sessão.', csrfToken: req.csrfToken() });
                    }
                    console.log('Sessão após login - loggedIn:', req.session.loggedIn, 'Session ID:', req.sessionID);
                    res.redirect('/admin');
                });
            } else {
                console.log('Senha incorreta para:', username);
                return res.render('login', { error: 'Senha incorreta.', csrfToken: req.csrfToken() });
            }
        });
    });
});

app.get('/admin', isAuthenticated, csrfProtection, (req, res) => {
    console.log('Acessando admin');
    db.all(`SELECT * FROM messages ORDER BY data DESC`, [], (err, rows) => {
        if (err) {
            console.error('Erro ao carregar mensagens:', err);
            return res.send('Erro ao carregar mensagens.');
        }
        res.render('admin', {
            messages: rows,
            csrfToken: req.csrfToken()
        });
    });
});

app.post('/admin/delete/:id', isAuthenticated, csrfProtection, (req, res) => {
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

app.get('/admin/logout', isAuthenticated, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao fazer logout:', err);
            return res.redirect('/admin');
        }
        res.redirect('/admin/login');
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
// ok