const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");

require("dotenv").config({
  path: __dirname + "/.env"
});

const Stripe = require("stripe");

console.log(
  "STRIPE KEY START:",
  process.env.STRIPE_SECRET_KEY?.substring(0, 15)
);

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();

/* Webhook Stripe : doit être AVANT express.json() */
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature error:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const commandeId = session.metadata.commande_id;

      if (commandeId) {
        await pool.query(
          `UPDATE commandes
           SET statut = 'paid'
           WHERE id = $1`,
          [commandeId]
        );

        console.log("Commande payée :", commandeId);
      }
    }

    res.json({ received: true });
  }
);

app.use(cors());
app.use(helmet());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("La Pala API fonctionne");
});

app.get("/api/plats", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM plats ORDER BY id");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password, role)
       VALUES ($1, $2, 'client')
       RETURNING id, email, role`,
      [email, hashedPassword]
    );

    res.json({
      message: "Compte créé",
      user: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur inscription" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT id, email, password, role FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role || "client"
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      message: "Connexion réussie",
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role || "client"
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur connexion" });
  }
});

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "Token manquant" });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Token invalide" });
  }
}

async function getUserRole(userId) {
  const result = await pool.query(
    "SELECT role FROM users WHERE id = $1",
    [userId]
  );

  if (result.rows.length === 0) return null;

  return result.rows[0].role;
}

async function adminMiddleware(req, res, next) {
  try {
    const role = await getUserRole(req.user.id);

    if (role !== "admin") {
      return res.status(403).json({
        error: "Accès réservé à l'administrateur"
      });
    }

    req.user.role = role;
    next();

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur vérification admin"
    });
  }
}

async function staffOrAdminMiddleware(req, res, next) {
  try {
    const role = await getUserRole(req.user.id);

    if (role !== "admin" && role !== "staff" && role !== "employee" && role !== "employe") {
      return res.status(403).json({
        error: "Accès réservé au personnel"
      });
    }

    req.user.role = role;
    next();

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur vérification personnel"
    });
  }
}

app.post("/api/commandes", authMiddleware, async (req, res) => {
  try {
    const {
      nom,
      email,
      total,
      mode = "livraison",
      adresse = "",
      items = []
    } = req.body;

    const commandeResult = await pool.query(
      `INSERT INTO commandes
      (user_id, nom, email, total, mode, adresse, statut)
      VALUES ($1, $2, $3, $4, $5, $6, 'pending')
      RETURNING *`,
      [
        req.user.id,
        nom,
        email,
        total,
        mode,
        adresse
      ]
    );

    const commande = commandeResult.rows[0];

    for (const item of items) {
      await pool.query(
        `INSERT INTO commande_items
        (commande_id, plat_id, quantite, prix_unitaire)
        VALUES ($1, $2, $3, $4)`,
        [
          commande.id,
          item.plat_id,
          item.quantite,
          item.prix_unitaire
        ]
      );
    }

    res.json({
      success: true,
      commande
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur commande"
    });
  }
});

app.get("/api/mes-commandes", authMiddleware, async (req, res) => {
  try {
    const commandesResult = await pool.query(
      `SELECT *
       FROM commandes
       WHERE user_id = $1
       ORDER BY date_commande DESC`,
      [req.user.id]
    );

    res.json(commandesResult.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur historique commandes"
    });
  }
});

app.post("/api/create-checkout-session", authMiddleware, async (req, res) => {
  try {
    const { total, commande_id } = req.body;

    if (!total || total <= 0) {
      return res.status(400).json({
        error: "Total invalide"
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",

      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: "Commande La Pala"
            },
            unit_amount: Math.round(Number(total) * 100)
          },
          quantity: 1
        }
      ],

      metadata: {
        commande_id: commande_id ? String(commande_id) : "",
        user_id: String(req.user.id)
      },

      success_url: "http://127.0.0.1:5501/pala.html#success",
      cancel_url: "http://127.0.0.1:5501/pala.html#cart"
    });

    res.json({
      url: session.url
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur Stripe"
    });
  }
});

app.post("/api/commande-payee", async (req, res) => {
  try {
    const { commande_id } = req.body;

    await pool.query(
      `UPDATE commandes
       SET statut = 'paid'
       WHERE id = $1`,
      [commande_id]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Erreur mise à jour commande"
    });
  }
});

/* =========================
   ROUTES ADMIN
   ========================= */

app.get("/api/admin/stats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalCommandes = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM commandes
    `);

    const totalCA = await pool.query(`
      SELECT COALESCE(SUM(total),0)::float AS total
      FROM commandes
      WHERE statut NOT IN ('annulee', 'cancelled')
    `);

    const preparation = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM commandes
      WHERE statut = 'preparation'
    `);

    const livraison = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM commandes
      WHERE statut IN ('livraison', 'delivery')
    `);

    const payees = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM commandes
      WHERE statut IN ('paid','accepted','preparation','ready','livraison','delivery','terminee','done')
    `);

    const aujourdHui = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM commandes
      WHERE DATE(date_commande) = CURRENT_DATE
    `);

    res.json({
      commandesTotal: totalCommandes.rows[0].total,
      commandesJour: aujourdHui.rows[0].total,
      chiffreAffaires: totalCA.rows[0].total,
      commandesPayees: payees.rows[0].total,
      enPreparation: preparation.rows[0].total,
      enLivraison: livraison.rows[0].total
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur statistiques admin"
    });
  }
});

/* Admin + staff peuvent voir les commandes */
app.get("/api/admin/commandes", authMiddleware, staffOrAdminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        c.id,
        c.user_id,
        c.nom,
        c.email,
        c.total,
        c.mode,
        c.adresse,
        c.statut,
        c.date_commande,
        COALESCE(
          json_agg(
            json_build_object(
              'plat_id', ci.plat_id,
              'quantite', ci.quantite,
              'prix_unitaire', ci.prix_unitaire,
              'nom_plat', p.nom
            )
          ) FILTER (WHERE ci.id IS NOT NULL),
          '[]'
        ) AS items
      FROM commandes c
      LEFT JOIN commande_items ci ON ci.commande_id = c.id
      LEFT JOIN plats p ON p.id = ci.plat_id
      GROUP BY c.id
      ORDER BY c.date_commande DESC`
    );

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur récupération commandes"
    });
  }
});

/* Admin + staff peuvent changer les statuts */
app.patch("/api/admin/commandes/:id/statut", authMiddleware, staffOrAdminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { statut } = req.body;

    const statutsAutorises = [
      "pending",
      "paid",
      "accepted",
      "preparation",
      "ready",
      "livraison",
      "delivery",
      "terminee",
      "done",
      "annulee",
      "cancelled"
    ];

    if (!statutsAutorises.includes(statut)) {
      return res.status(400).json({
        error: "Statut invalide"
      });
    }

    const result = await pool.query(
      `UPDATE commandes
       SET statut = $1
       WHERE id = $2
       RETURNING *`,
      [statut, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Commande introuvable"
      });
    }

    res.json({
      success: true,
      commande: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur modification statut"
    });
  }
});

/* Les routes plats restent réservées admin uniquement */
app.post("/api/admin/plats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { nom, description, prix, categorie, image } = req.body;

    if (!nom || !prix || !categorie) {
      return res.status(400).json({
        error: "Nom, prix et catégorie obligatoires"
      });
    }

    const result = await pool.query(
      `INSERT INTO plats (nom, description, prix, categorie, image)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        nom,
        description || "",
        prix,
        categorie,
        image || ""
      ]
    );

    res.json({
      success: true,
      plat: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur ajout plat"
    });
  }
});

app.patch("/api/admin/plats/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { nom, description, prix, categorie, image } = req.body;

    if (!nom || !prix || !categorie) {
      return res.status(400).json({
        error: "Nom, prix et catégorie obligatoires"
      });
    }

    const result = await pool.query(
      `UPDATE plats
       SET nom = $1,
           description = $2,
           prix = $3,
           categorie = $4,
           image = $5
       WHERE id = $6
       RETURNING *`,
      [
        nom,
        description || "",
        prix,
        categorie,
        image || "",
        id
      ]
    );

    res.json({
      success: true,
      plat: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur modification plat"
    });
  }
});

app.delete("/api/admin/plats/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      `DELETE FROM plats
       WHERE id = $1`,
      [id]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Erreur suppression plat"
    });
  }
});

app.listen(3000, () => {
  console.log("Serveur lancé sur http://localhost:3000");
});