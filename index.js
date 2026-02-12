const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(express.json());

// --------------------
// CORS
// --------------------
const normalizeOrigin = (o) => (o ? String(o).trim().replace(/\/$/, "") : null);

const allowedOrigins = new Set(
  [
    normalizeOrigin(process.env.FRONTEND_ORIGIN), // EJ: https://fnc-coffee-gateway-np9a.vercel.app
    "http://localhost:5173",
    "http://localhost:5175",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5175",
  ].filter(Boolean)
);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // Postman/curl
    const o = normalizeOrigin(origin);
    if (allowedOrigins.has(o)) return cb(null, true);
    return cb(new Error(`CORS bloqueado para: ${origin}`));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

// --------------------
// DB (Neon / Postgres)
// --------------------
if (!process.env.DATABASE_URL) {
  console.warn("⚠️ Falta DATABASE_URL en variables de entorno (Render -> Environment).");
}

// Neon requiere SSL. Usamos rejectUnauthorized:false para evitar errores de certificado.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// --------------------
// Roles válidos
// --------------------
const ROLES_VALIDOS = new Set(["Director", "CoordProyectos", "Financiera"]);

// --------------------
// Health
// --------------------
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.json({ ok: true, db: true });
  } catch (e) {
    console.error("HEALTH_ERROR:", e?.message || e);
    return res.status(500).json({ ok: false, db: false });
  }
});

// --------------------
// Login
// Body: { usuario, password }
// --------------------
app.post("/login", async (req, res) => {
  try {
    const { usuario, password } = req.body || {};
    console.log("LOGIN_REQ:", { usuario, hasPassword: !!password });

    if (!usuario || !password) {
      return res.status(400).json({ message: "Faltan credenciales" });
    }

    const userUpper = String(usuario).toUpperCase().trim();

    const result = await pool.query(
      `SELECT id, usuario, password_hash, rol, activo
       FROM public.usuarios
       WHERE usuario = $1
       LIMIT 1`,
      [userUpper]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    const user = result.rows[0];

    // En Postgres activo es boolean
    if (user.activo !== true) {
      return res.status(401).json({ message: "Usuario inactivo" });
    }

    const hash = String(user.password_hash || "").trim();
    const ok = await bcrypt.compare(String(password), hash);

    if (!ok) {
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    const rol = String(user.rol || "").trim();
    if (!ROLES_VALIDOS.has(rol)) {
      return res.status(403).json({ message: "Rol no autorizado" });
    }

    await pool.query("UPDATE public.usuarios SET ultimo_login = NOW() WHERE id = $1", [
      user.id,
    ]);

    return res.json({ usuario: user.usuario, rol });
  } catch (e) {
    console.error("LOGIN_ERROR:", e?.message || e);
    return res.status(500).json({ message: "Error interno del servidor" });
  }
});

// --------------------
// Listen (Render)
// --------------------
const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Auth API corriendo en puerto ${PORT}`);
  console.log("✅ FRONTEND_ORIGIN permitido:", normalizeOrigin(process.env.FRONTEND_ORIGIN));
});
