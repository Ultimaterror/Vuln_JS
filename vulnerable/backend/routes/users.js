const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');
const bcrypt = require('bcrypt');

// Route pour lister les utilisateurs
router.get('/', async (req, res) => {
  const sql = 'SELECT id, username, email, role, created_at FROM users';
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des utilisateurs :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

// Route pour récupérer un utilisateur spécifique
router.get('/:id', async (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT id, username, email, role, created_at FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'utilisateur' });
  }
});

// Route pour supprimer un utilisateur
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM users WHERE id = ?';
  try {
    await req.db.execute(sql, [id]);
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur' });
  }
});

// Route pour modifier un utilisateur
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const { username, email, password, role } = req.body;

  try {
    let sql;
    let params;

    if (password) {
      const hashedPassword = bcrypt.hashSync(password, 10);
      sql = 'UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?';
      params = [username, email, hashedPassword, role, id];
    } else {
      sql = 'UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?';
      params = [username, email, role, id];
    }

    await req.db.execute(sql, params);

    // Return user without password
    const userResponse = { id, username, email, role };
    res.json({ message: 'Utilisateur modifié avec succès', user: userResponse });
  } catch (err) {
    console.error('Erreur lors de la modification de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur' });
  }
});

module.exports = router;
