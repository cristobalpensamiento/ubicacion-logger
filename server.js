const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./database.db');
db.run(\`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
)\`);
db.run(\`CREATE TABLE IF NOT EXISTS registros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    hora TEXT,
    latitud REAL,
    longitud REAL,
    FOREIGN KEY(user_id) REFERENCES usuarios(id)
)\`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'clave-secreta',
  resave: false,
  saveUninitialized: false
}));

app.post('/api/registro', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(\`INSERT INTO usuarios (email, password) VALUES (?, ?)\`, [email, hash], function(err) {
    if (err) return res.status(400).send("Usuario ya existe");
    req.session.userId = this.lastID;
    res.redirect('/index.html');
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get(\`SELECT * FROM usuarios WHERE email = ?\`, [email], async (err, user) => {
    if (!user) return res.status(400).send("Usuario no encontrado");
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).send("Contraseña incorrecta");
    req.session.userId = user.id;
    res.redirect('/index.html');
  });
});

app.post('/api/registrar', (req, res) => {
  if (!req.session.userId) return res.status(403).send("No autenticado");
  const { hora, lat, lng } = req.body;
  db.run(\`INSERT INTO registros (user_id, hora, latitud, longitud) VALUES (?, ?, ?, ?)\`,
    [req.session.userId, hora, lat, lng],
    (err) => {
      if (err) return res.status(500).send("Error al guardar");
      res.send("Guardado");
    });
});

app.get('/api/mis-registros', (req, res) => {
  if (!req.session.userId) return res.status(403).send("No autenticado");
  db.all(\`SELECT * FROM registros WHERE user_id = ? ORDER BY id DESC\`, [req.session.userId], (err, rows) => {
    if (err) return res.status(500).send("Error");
    res.json(rows);
  });
});

app.listen(PORT, () => console.log(\`Servidor en puerto \${PORT}\`));