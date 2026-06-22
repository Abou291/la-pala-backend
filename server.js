/* =========================================================
   LA PALA — server.js
   Backend Express sécurisé (Render + PostgreSQL + Stripe)
   ========================================================= */

require("dotenv").config({
  path: __dirname + "/.env"
});

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const Stripe = require("stripe");

const pool = require("./db");

/* =========================================================
   1. VÉRIFICATION DES VARIABLES D'ENVIRONNEMENT
   ========================================================= */

const REQUIRED_ENV = [
  "DATABASE_URL",
  "JWT_SECRET",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "FRONTEND_URL"
];

const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);

if (missingEnv.length > 0) {
  throw new Error(
    "Variables d'environnement manquantes : " +
    missingEnv.join(", ") +
    ". Le serveur ne peut pas démarrer."
  );
}

const FRONTEND_URL = process.env.FRONTEND_URL.replace(/\/+$/, "");

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();

// Render tourne derrière un proxy : nécessaire pour le rate-limit et l'IP réelle.
app.set("trust proxy", 1);

/* =========================================================
   DÉTECTION DU SCHÉMA
   Permet d'utiliser les colonnes/tables optionnelles
   seulement si elles existent réellement en base.
   ========================================================= */

const SCHEMA = {
  plats: {
    archive: false,
    disponible: false,
    ordre: false,
    allergenes: false
  },
  commandes: {
    sous_total: false,
    frais_livraison: false,
    stripe_session_id: false,
    stripe_payment_intent: false
  },
  restaurant_settings: false,
  stripe_events: false
};

async function detectSchema() {
  try {
    const cols = await pool.query(`
      SELECT table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN ('plats', 'commandes')
    `);

    cols.rows.forEach(({ table_name, column_name }) => {
      if (SCHEMA[table_name] && column_name in SCHEMA[table_name]) {
        SCHEMA[table_name][column_name] = true;
      }
    });

    const tables = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('restaurant_settings', 'stripe_events')
    `);

    tables.rows.forEach(({ table_name }) => {
      SCHEMA[table_name] = true;
    });

    console.log("Schéma détecté :", JSON.stringify(SCHEMA));

  } catch (err) {
    console.error(
      "Détection du schéma impossible, mode minimal activé :",
      err.message
    );
  }
}

/* =========================================================
   8. WEBHOOK STRIPE
   Doit être déclaré AVANT express.json() (corps brut requis)
   ========================================================= */

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
      console.error("Erreur signature webhook :", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Idempotence : ne pas retraiter un événement déjà reçu
    if (SCHEMA.stripe_events) {
      try {
        const insertEvent = await pool.query(
          `INSERT INTO stripe_events (event_id, type)
           VALUES ($1, $2)
           ON CONFLICT (event_id) DO NOTHING
           RETURNING event_id`,
          [event.id, event.type]
        );

        if (insertEvent.rows.length === 0) {
          return res.json({ received: true, duplicate: true });
        }
      } catch (err) {
        console.error("Erreur idempotence stripe_events :", err.message);
        // On continue quand même : mieux vaut traiter que perdre l'événement.
      }
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const commandeId = session.metadata && session.metadata.commande_id;

      if (commandeId) {
        try {
          const commandeRes = await pool.query(
            "SELECT id, total FROM commandes WHERE id = $1",
            [commandeId]
          );

          if (commandeRes.rows.length === 0) {
            console.error("Webhook : commande introuvable", commandeId);
            return res.json({ received: true });
          }

          const commande = commandeRes.rows[0];
          const attendu = Math.round(Number(commande.total) * 100);

          if (session.amount_total !== attendu) {
            console.error(
              "Webhook : montant non concordant. Attendu",
              attendu,
              "reçu",
              session.amount_total
            );
            return res.json({ received: true, mismatch: true });
          }

          // Construction dynamique de l'UPDATE selon les colonnes existantes
          const sets = ["statut = 'paid'"];
          const values = [];
          let i = 1;

          if (SCHEMA.commandes.stripe_session_id) {
            sets.push(`stripe_session_id = $${i++}`);
            values.push(session.id);
          }

          if (SCHEMA.commandes.stripe_payment_intent && session.payment_intent) {
            sets.push(`stripe_payment_intent = $${i++}`);
            values.push(session.payment_intent);
          }

          values.push(commandeId);

          await pool.query(
            `UPDATE commandes
             SET ${sets.join(", ")}
             WHERE id = $${i}`,
            values
          );

          console.log("Commande payée confirmée :", commandeId);

        } catch (err) {
          console.error("Erreur traitement webhook :", err);
          // On renvoie 200 quand même pour éviter les retries en boucle
          // sur une erreur applicative (Stripe ré-essaie sur les non-2xx).
          return res.json({ received: true, error: true });
        }
      }
    }

    res.json({ received: true });
  }
);

/* =========================================================
   2. CORS RESTREINT
   ========================================================= */

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

app.use(helmet());
app.use(express.json());

/* =========================================================
   3. RATE LIMIT
   ========================================================= */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Trop de tentatives. Réessayez dans quelques minutes."
  }
});

/* =========================================================
   ROUTE RACINE
   ========================================================= */

app.get("/", (req, res) => {
  res.send("La Pala API fonctionne");
});

/* =========================================================
   11. GET /api/plats (carte publique)
   ========================================================= */

app.get("/api/plats", async (req, res) => {
  try {
    const where = SCHEMA.plats.archive
      ? "WHERE COALESCE(archive, false) = false"
      : "";

    const order = SCHEMA.plats.ordre
      ? "ORDER BY COALESCE(ordre, id), id"
      : "ORDER BY id";

    const result = await pool.query(
      `SELECT * FROM plats ${where} ${order}`
    );

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

/* =========================================================
   4. REGISTER (sécurisé)
   ========================================================= */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({ error: "Email invalide" });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 8 caractères"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Le rôle est TOUJOURS 'client' : l'utilisateur ne peut jamais le choisir.
    const result = await pool.query(
      `INSERT INTO users (email, password, role)
       VALUES ($1, $2, 'client')
       RETURNING id, email, role`,
      [email, hashedPassword]
    );

    res.status(201).json({
      message: "Compte créé",
      user: result.rows[0]
    });

  } catch (err) {
    // 23505 = violation de contrainte unique (email déjà utilisé)
    if (err.code === "23505") {
      return res.status(409).json({ error: "Cet email est déjà utilisé" });
    }

    console.error(err);
    res.status(500).json({ error: "Erreur inscription" });
  }
});

/* =========================================================
   LOGIN
   ========================================================= */

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

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

/* =========================================================
   MIDDLEWARES
   ========================================================= */

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
    res.status(500).json({ error: "Erreur vérification admin" });
  }
}

async function staffOrAdminMiddleware(req, res, next) {
  try {
    const role = await getUserRole(req.user.id);

    if (
      role !== "admin" &&
      role !== "staff" &&
      role !== "employee" &&
      role !== "employe"
    ) {
      return res.status(403).json({
        error: "Accès réservé au personnel"
      });
    }

    req.user.role = role;
    next();

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur vérification personnel" });
  }
}

/* =========================================================
   5. CRÉATION DE COMMANDE (prix recalculés côté serveur)
   ========================================================= */

app.post("/api/commandes", authMiddleware, async (req, res) => {
  const {
    nom,
    email,
    mode = "livraison",
    adresse = "",
    items = []
  } = req.body;

  // Validations de base
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Panier vide" });
  }

  if (mode !== "livraison" && mode !== "retrait") {
    return res.status(400).json({ error: "Mode de commande invalide" });
  }

  if (mode === "livraison" && String(adresse).trim() === "") {
    return res.status(400).json({
      error: "Adresse de livraison obligatoire"
    });
  }

  // Nettoyage des items : on ne garde que plat_id + quantite valides
  const lignes = [];

  for (const item of items) {
    const platId = Number(item.plat_id);
    const quantite = Number(item.quantite);

    if (!Number.isInteger(platId) || platId <= 0) {
      return res.status(400).json({ error: "Plat invalide dans le panier" });
    }

    if (!Number.isInteger(quantite) || quantite <= 0 || quantite > 99) {
      return res.status(400).json({ error: "Quantité invalide" });
    }

    lignes.push({ platId, quantite });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Récupération des plats réels en base
    const platIds = lignes.map(l => l.platId);

    const platsRes = await client.query(
      "SELECT * FROM plats WHERE id = ANY($1)",
      [platIds]
    );

    const platsMap = {};
    platsRes.rows.forEach(p => { platsMap[p.id] = p; });

    let sousTotal = 0;

    for (const ligne of lignes) {
      const plat = platsMap[ligne.platId];

      if (!plat) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Plat #${ligne.platId} introuvable`
        });
      }

      // Refus si archivé ou indisponible (colonnes optionnelles)
      if (plat.archive === true) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Le plat "${plat.nom}" n'est plus disponible`
        });
      }

      if (plat.disponible === false) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Le plat "${plat.nom}" est actuellement épuisé`
        });
      }

      sousTotal += Number(plat.prix) * ligne.quantite;
    }

    // Frais de livraison (table optionnelle restaurant_settings)
    let fraisLivraison = 0;

    if (mode === "livraison" && SCHEMA.restaurant_settings) {
      try {
        const settingsRes = await client.query(
          `SELECT valeur
           FROM restaurant_settings
           WHERE cle = 'frais_livraison'
           LIMIT 1`
        );

        if (settingsRes.rows.length > 0) {
          fraisLivraison = Number(settingsRes.rows[0].valeur) || 0;
        }
      } catch (err) {
        console.error("Lecture frais_livraison impossible :", err.message);
      }
    }

    const total = sousTotal + fraisLivraison;

    // Email/nom : on privilégie le token pour éviter l'usurpation
    const emailFinal = req.user.email || email || "";
    const nomFinal = nom || (emailFinal ? emailFinal.split("@")[0] : "Client");

    // Construction dynamique de l'INSERT selon les colonnes existantes
    const cols = ["user_id", "nom", "email", "total", "mode", "adresse", "statut"];
    const values = [req.user.id, nomFinal, emailFinal, total, mode, adresse, "pending"];

    if (SCHEMA.commandes.sous_total) {
      cols.push("sous_total");
      values.push(sousTotal);
    }

    if (SCHEMA.commandes.frais_livraison) {
      cols.push("frais_livraison");
      values.push(fraisLivraison);
    }

    const placeholders = values.map((_, idx) => `$${idx + 1}`).join(", ");

    const commandeResult = await client.query(
      `INSERT INTO commandes (${cols.join(", ")})
       VALUES (${placeholders})
       RETURNING *`,
      values
    );

    const commande = commandeResult.rows[0];

    // Insertion des lignes avec le prix RÉEL en base
    for (const ligne of lignes) {
      const plat = platsMap[ligne.platId];

      await client.query(
        `INSERT INTO commande_items
         (commande_id, plat_id, quantite, prix_unitaire)
         VALUES ($1, $2, $3, $4)`,
        [commande.id, ligne.platId, ligne.quantite, plat.prix]
      );
    }

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      commande
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Erreur commande" });

  } finally {
    client.release();
  }
});

/* =========================================================
   HISTORIQUE CLIENT
   ========================================================= */

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
    res.status(500).json({ error: "Erreur historique commandes" });
  }
});

/* =========================================================
   6. CHECKOUT STRIPE (total pris en base, jamais du client)
   ========================================================= */

app.post("/api/create-checkout-session", authMiddleware, async (req, res) => {
  try {
    const commandeId = Number(req.body.commande_id);

    if (!Number.isInteger(commandeId) || commandeId <= 0) {
      return res.status(400).json({ error: "Commande invalide" });
    }

    const commandeRes = await pool.query(
      "SELECT * FROM commandes WHERE id = $1",
      [commandeId]
    );

    if (commandeRes.rows.length === 0) {
      return res.status(404).json({ error: "Commande introuvable" });
    }

    const commande = commandeRes.rows[0];

    // La commande doit appartenir à l'utilisateur connecté
    if (commande.user_id !== req.user.id) {
      return res.status(403).json({ error: "Accès refusé" });
    }

    if (commande.statut !== "pending") {
      return res.status(400).json({
        error: "Cette commande n'est plus en attente de paiement"
      });
    }

    const total = Number(commande.total);

    if (!(total > 0)) {
      return res.status(400).json({ error: "Total invalide" });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",

      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: { name: `Commande La Pala #${commande.id}` },
            unit_amount: Math.round(total * 100)
          },
          quantity: 1
        }
      ],

      metadata: {
        commande_id: String(commande.id),
        user_id: String(req.user.id)
      },

      success_url: `${FRONTEND_URL}/#success`,
      cancel_url: `${FRONTEND_URL}/#cart`
    });

    // Enregistrement du session_id si la colonne existe
    if (SCHEMA.commandes.stripe_session_id) {
      try {
        await pool.query(
          "UPDATE commandes SET stripe_session_id = $1 WHERE id = $2",
          [session.id, commande.id]
        );
      } catch (err) {
        console.error("Enregistrement stripe_session_id impossible :", err.message);
      }
    }

    res.json({ url: session.url });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur Stripe" });
  }
});

/* =========================================================
   7. ROUTE /api/commande-payee DÉSACTIVÉE (410 Gone)
   Le paiement est confirmé UNIQUEMENT par le webhook Stripe.
   ========================================================= */

app.post("/api/commande-payee", (req, res) => {
  res.status(410).json({
    error: "Route désactivée. Paiement géré par le webhook Stripe."
  });
});

/* =========================================================
   ROUTES ADMIN — STATISTIQUES
   ========================================================= */

app.get("/api/admin/stats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalCommandes = await pool.query(`
      SELECT COUNT(*)::int AS total FROM commandes
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
    res.status(500).json({ error: "Erreur statistiques admin" });
  }
});

/* =========================================================
   13. GET /api/admin/commandes (admin + staff)
   ========================================================= */

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
    res.status(500).json({ error: "Erreur récupération commandes" });
  }
});

/* =========================================================
   14. PATCH /api/admin/commandes/:id/statut (admin + staff)
   ========================================================= */

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
      return res.status(400).json({ error: "Statut invalide" });
    }

    const result = await pool.query(
      `UPDATE commandes
       SET statut = $1
       WHERE id = $2
       RETURNING *`,
      [statut, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Commande introuvable" });
    }

    res.json({
      success: true,
      commande: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur modification statut" });
  }
});

/* =========================================================
   ROUTES ADMIN — PLATS (admin uniquement)
   ========================================================= */

app.post("/api/admin/plats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { nom, description, prix, categorie, image, allergenes, ordre } = req.body;

    if (!nom || !prix || !categorie) {
      return res.status(400).json({
        error: "Nom, prix et catégorie obligatoires"
      });
    }

    // Construction dynamique selon les colonnes existantes
    const cols = ["nom", "description", "prix", "categorie", "image"];
    const values = [nom, description || "", prix, categorie, image || ""];

    if (SCHEMA.plats.disponible) {
      cols.push("disponible");
      values.push(true);
    }

    if (SCHEMA.plats.archive) {
      cols.push("archive");
      values.push(false);
    }

    if (SCHEMA.plats.allergenes && allergenes !== undefined) {
      cols.push("allergenes");
      values.push(allergenes || "");
    }

    if (SCHEMA.plats.ordre && ordre !== undefined) {
      cols.push("ordre");
      values.push(Number(ordre) || 0);
    }

    const placeholders = values.map((_, idx) => `$${idx + 1}`).join(", ");

    const result = await pool.query(
      `INSERT INTO plats (${cols.join(", ")})
       VALUES (${placeholders})
       RETURNING *`,
      values
    );

    res.status(201).json({
      success: true,
      plat: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur ajout plat" });
  }
});

/* =========================================================
   12. PATCH /api/admin/plats/:id
   nom, prix, categorie obligatoires.
   Accepte aussi disponible, archive, allergenes, ordre.
   ========================================================= */

app.patch("/api/admin/plats/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      nom,
      description,
      prix,
      categorie,
      image,
      disponible,
      archive,
      allergenes,
      ordre
    } = req.body;

    if (!nom || !prix || !categorie) {
      return res.status(400).json({
        error: "Nom, prix et catégorie obligatoires"
      });
    }

    const sets = [];
    const values = [];
    let i = 1;

    const addSet = (col, val) => {
      sets.push(`${col} = $${i++}`);
      values.push(val);
    };

    addSet("nom", nom);
    addSet("description", description || "");
    addSet("prix", prix);
    addSet("categorie", categorie);
    addSet("image", image || "");

    if (SCHEMA.plats.disponible && disponible !== undefined) {
      addSet("disponible", !!disponible);
    }

    if (SCHEMA.plats.archive && archive !== undefined) {
      addSet("archive", !!archive);
    }

    if (SCHEMA.plats.allergenes && allergenes !== undefined) {
      addSet("allergenes", allergenes || "");
    }

    if (SCHEMA.plats.ordre && ordre !== undefined) {
      addSet("ordre", Number(ordre) || 0);
    }

    values.push(id);

    const result = await pool.query(
      `UPDATE plats
       SET ${sets.join(", ")}
       WHERE id = $${i}
       RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Plat introuvable" });
    }

    res.json({
      success: true,
      plat: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur modification plat" });
  }
});

/* =========================================================
   10. SOFT DELETE des plats
   On archive au lieu de supprimer pour garder l'historique.
   Fallback en DELETE si la colonne archive n'existe pas.
   ========================================================= */

app.delete("/api/admin/plats/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    if (SCHEMA.plats.archive) {
      const sets = ["archive = true"];

      if (SCHEMA.plats.disponible) {
        sets.push("disponible = false");
      }

      const result = await pool.query(
        `UPDATE plats
         SET ${sets.join(", ")}
         WHERE id = $1
         RETURNING *`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Plat introuvable" });
      }

      return res.json({ success: true, plat: result.rows[0] });
    }

    // Fallback : suppression physique (peut échouer si référencé par une commande)
    await pool.query("DELETE FROM plats WHERE id = $1", [id]);

    res.json({ success: true });

  } catch (err) {
    console.error(err);

    // 23503 = violation de clé étrangère (plat utilisé dans une commande)
    if (err.code === "23503") {
      return res.status(409).json({
        error: "Ce plat est lié à des commandes et ne peut pas être supprimé."
      });
    }

    res.status(500).json({ error: "Erreur suppression plat" });
  }
});

/* =========================================================
   9. DÉMARRAGE
   ========================================================= */

const PORT = process.env.PORT || 3000;

detectSchema()
  .catch(() => { /* déjà loggé */ })
  .finally(() => {
    app.listen(PORT, () => {
      console.log(`Serveur lancé sur le port ${PORT}`);
    });
  });