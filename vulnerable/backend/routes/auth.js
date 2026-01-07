const express = require('express');
const router = express.Router();
const { generateToken } = require('../utils/jwt');
const bcrypt = require('bcrypt');
const { validatePassword } = require('../utils/validation');
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');

// Route pour s'inscrire
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  const validation = validatePassword(password);
  if (!validation.isValid) {
    return res.status(400).json({ error: validation.message });
  }

  const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
  const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  try {
    const [existingUsers] = await req.db.execute(checkSql, [email, username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }
    const [results] = await req.db.execute(insertSql, [username, email, bcrypt.hashSync(password, 10)]);
    res.status(201).json({ message: 'Utilisateur créé avec succès', id: results.insertId });

  } catch (err) {
    console.error('Erreur lors de l\'inscription :', err);
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

// Route pour se connecter
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  try {
    const [results] = await req.db.execute(sql, [email]);
    if (results.length === 0) {
      return res.status(401).json({ error: 'Email incorrect' });
    }
    const user = results[0];
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }
    const { password: _p, email: _e, created_at: _c, ...userWithoutSensibleData } = user;
    const token = generateToken(userWithoutSensibleData);
    res.json({ message: 'Connexion réussie', token, user: userWithoutSensibleData });
  } catch (err) {
    console.error('Erreur lors de la connexion :', err);
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

// Route pour vérifier si l'utilisateur est admin
router.get('/access-admin', authenticate, authorizeAdmin, (req, res) => {
  res.json({ isAdmin: true });
});

module.exports = router;
