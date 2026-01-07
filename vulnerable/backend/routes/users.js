const express = require("express");
const router = express.Router();
const {
	authenticate,
	authorizeAdmin,
} = require("../middlewares/authMiddleware");
const bcrypt = require("bcrypt");
const { validatePassword } = require("../utils/validation");

// Route pour lister les utilisateurs (admin seulement)
router.get("/", authenticate, authorizeAdmin, async (req, res) => {
	const sql = "SELECT id, username, email, role, created_at FROM users";
	try {
		const [results] = await req.db.execute(sql);
		res.json(results);
	} catch (err) {
		console.error("Erreur lors de la récupération des utilisateurs :", err);
		res
			.status(500)
			.json({ error: "Erreur lors de la récupération des utilisateurs" });
	}
});

// Route pour récupérer un utilisateur spécifique (owner or admin)
router.get("/:id", authenticate, async (req, res) => {
	const { id } = req.params;
	const sql =
		"SELECT id, username, email, role, created_at FROM users WHERE id = ?";
	try {
		const [results] = await req.db.execute(sql, [id]);
		if (results.length === 0) {
			return res.status(404).json({ error: "Utilisateur introuvable" });
		}
		const result = results[0];
		if (result.id !== req.user.id && req.user.role !== "admin") {
			return res.status(403).json({
				error:
					"Accès interdit : vous n'êtes pas le propriétaire de cet utilisateur",
			});
		}
		res.json(result);
	} catch (err) {
		console.error("Erreur lors de la récupération de l'utilisateur :", err);
		res
			.status(500)
			.json({ error: "Erreur lors de la récupération de l'utilisateur" });
	}
});

// Route pour supprimer un utilisateur (owner or admin)
router.delete("/:id", authenticate, async (req, res) => {
	const { id } = req.params;
	const checkSql = "SELECT * FROM users WHERE id = ?";
	const sql = "DELETE FROM users WHERE id = ?";
	try {
		const [existingUsers] = await req.db.execute(checkSql, [id]);
		if (existingUsers.length === 0) {
			return res.status(404).json({ error: "Utilisateur introuvable" });
		}
		const result = existingUsers[0];
		if (result.id !== req.user.id && req.user.role !== "admin") {
			return res.status(403).json({
				error:
					"Accès interdit : vous n'êtes pas le propriétaire de cet utilisateur",
			});
		}
		await req.db.execute(sql, [id]);
		res.json({ message: "Utilisateur supprimé avec succès" });
	} catch (err) {
		console.error("Erreur lors de la suppression de l'utilisateur :", err);
		res
			.status(500)
			.json({ error: "Erreur lors de la suppression de l'utilisateur" });
	}
});

// Route pour modifier un utilisateur (owner or admin)
router.put("/:id", authenticate, async (req, res) => {
	const { id } = req.params;
	const { username, email, password, role } = req.body;

	try {
		const checkSql = "SELECT * FROM users WHERE id = ?";
		const [existingUsers] = await req.db.execute(checkSql, [id]);
		if (existingUsers.length === 0) {
			return res.status(404).json({ error: "Utilisateur introuvable" });
		}
		const result = existingUsers[0];
		if (result.id !== req.user.id && req.user.role !== "admin") {
			return res.status(403).json({
				error:
					"Accès interdit : vous n'êtes pas le propriétaire de cet utilisateur",
			});
		}

		let sql;
		let params;

		if (password) {
			const validation = validatePassword(password);
			if (!validation.isValid) {
				return res.status(400).json({ error: validation.message });
			}
			const hashedPassword = bcrypt.hashSync(password, 10);
			sql =
				"UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?";
			params = [username, email, hashedPassword, role, id];
		} else {
			sql = "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?";
			params = [username, email, role, id];
		}

		await req.db.execute(sql, params);

		// Return user without password
		const userResponse = { id, username, email, role };
		res.json({
			message: "Utilisateur modifié avec succès",
			user: userResponse,
		});
	} catch (err) {
		console.error("Erreur lors de la modification de l'utilisateur :", err);
		res
			.status(500)
			.json({ error: "Erreur lors de la modification de l'utilisateur" });
	}
});

module.exports = router;
