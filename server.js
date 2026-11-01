const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const SECRET = process.env.SECRET;
if (!SECRET) { console.error('Defina a variavel SECRET'); process.exit(1); }

const db = new Database(process.env.DB_PATH || 'app.db');
db.exec('CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, pass TEXT NOT NULL, photo TEXT, created INTEGER)');
db.exec('CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, chat TEXT NOT NULL, user TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL)');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const allowed = (chat, u) => !chat.includes('|') || chat.split('|').includes(u);
const okName = n => /^[a-z0-9_.]{3,20}$/.test(n || '');
const token = name => jwt.sign({ name }, SECRET, { expiresIn: '30d' });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(t, SECRET).name;
    next();
  } catch (e) { res.status(401).json({ erro: 'Sessao invalida' }); }
}

app.get('/', (req, res) => res.send('ok'));

app.post('/register', (req, res) => {
  const { name, pass } = req.body;
  if (!okName(name)) return res.status(400).json({ erro: 'Usuario invalido' });
  if (!pass || pass.length < 4) return res.status(400).json({ erro: 'Senha curta' });
  if (db.prepare('SELECT 1 FROM users WHERE name=?').get(name)) return res.status(409).json({ erro: 'Usuario ja existe' });
  db.prepare('INSERT INTO users(name,pass,created) VALUES(?,?,?)').run(name, bcrypt.hashSync(pass, 10), Date.now());
  res.json({ token: token(name) });
});

app.post('/login', (req, res) => {
  const { name, pass } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE name=?').get(name || '');
  if (!u || !bcrypt.compareSync(pass || '', u.pass)) return res.status(401).json({ erro: 'Usuario ou senha incorretos' });
  res.json({ token: token(u.name) });
});

app.get('/me', auth, (req, res) => {
  res.json(db.prepare('SELECT name,photo,created FROM users WHERE name=?').get(req.user));
});

app.put('/me/photo', auth, (req, res) => {
  db.prepare('UPDATE users SET photo=? WHERE name=?').run(req.body.photo || null, req.user);
  res.json({ ok: true });
});

app.put('/me/password', auth, (req, res) => {
  const { old, nova } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE name=?').get(req.user);
  if (!bcrypt.compareSync(old || '', u.pass)) return res.status(401).json({ erro: 'Senha atual incorreta' });
  if (!nova || nova.length < 4) return res.status(400).json({ erro: 'Senha curta' });
  db.prepare('UPDATE users SET pass=? WHERE name=?').run(bcrypt.hashSync(nova, 10), req.user);
  res.json({ ok: true });
});

app.put('/me/name', auth, (req, res) => {
  const n = req.body.name;
  if (!okName(n)) return res.status(400).json({ erro: 'Usuario invalido' });
  if (db.prepare('SELECT 1 FROM users WHERE name=?').get(n)) return res.status(409).json({ erro: 'Usuario ja existe' });
  db.prepare('UPDATE users SET name=? WHERE name=?').run(n, req.user);
  db.prepare('UPDATE messages SET user=? WHERE user=?').run(n, req.user);
  res.json({ token: token(n) });
});

app.delete('/me', auth, (req, res) => {
  db.prepare('DELETE FROM users WHERE name=?').run(req.user);
  res.json({ ok: true });
});

app.get('/users/:name', auth, (req, res) => {
  const u = db.prepare('SELECT name,photo FROM users WHERE name=?').get(req.params.name);
  if (!u) return res.status(404).json({ erro: 'Nao encontrado' });
  res.json(u);
});

app.get('/messages/:chat', auth, (req, res) => {
  if (!allowed(req.params.chat, req.user)) return res.status(403).json({ erro: 'Sem acesso' });
  res.json(db.prepare('SELECT user,text,ts FROM messages WHERE chat=? ORDER BY id DESC LIMIT 200').all(req.params.chat).reverse());
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, SECRET).name; next(); }
  catch (e) { next(new Error('auth')); }
});

io.on('connection', socket => {
  socket.join('u:' + socket.user);
  socket.on('entrar', chat => { if (typeof chat === 'string' && allowed(chat, socket.user)) socket.join(chat); });
  socket.on('msg', ({ chat, text }) => {
    if (typeof chat !== 'string' || typeof text !== 'string') return;
    if (!allowed(chat, socket.user)) return;
    text = text.trim().slice(0, 2000);
    if (!text) return;
    const ts = Date.now();
    db.prepare('INSERT INTO messages(chat,user,text,ts) VALUES(?,?,?,?)').run(chat, socket.user, text, ts);
    let alvo = io.to(chat);
    if (chat.includes('|')) chat.split('|').forEach(n => { alvo = alvo.to('u:' + n); });
    alvo.emit('msg', { chat, user: socket.user, text, ts });
  });
});

server.listen(process.env.PORT || 3000, () => console.log('Servidor rodando'));

