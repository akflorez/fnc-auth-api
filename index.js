const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());

// ✅ Allowlist robusta (localhost + 127.0.0.1 + puertos típicos)
const allowedOrigins = new Set(
  [
    process.env.FRONTEND_ORIGIN,      // ej: http://localhost:5175
    "http://localhost:5173",
    "http://localhost:5175",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5175",
  ].filter(Boolean)
);

const corsOptions = {
  origin: (origin, cb) => {
    // Permite requests sin Origin (Postman/curl)
    if (!origin) return cb(null, true);
    if (allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error(`CORS bloqueado para: ${origin}`));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// ✅ OJO Express 5: evitar "*" string, usar regex para OPTIONS global
app.options(/.*/, cors(corsOptions));

// ✅ Pool desde .env
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "federacion-1",
  port: Number(process.env.DB_PORT || 3306),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ✅ Roles válidos (deben coincidir con tu DB)
const ROLES_VALIDOS = new Set(["Director", "CoordProyectos", "Financiera"]);

// ✅ Health
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: true });
  } catch (e) {
    console.error("HEALTH_ERROR:", e);
    res.status(500).json({ ok: false, db: false });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { usuario, password } = req.body || {};
    console.log("LOGIN_REQ:", { usuario, hasPassword: !!password }); // debug rápido

    if (!usuario || !password) {
      return res.status(400).json({ message: "Faltan credenciales" });
    }

    const userUpper = String(usuario).toUpperCase().trim();

    const [rows] = await pool.query(
      "SELECT id, usuario, password_hash, rol, activo FROM usuarios WHERE usuario = ? LIMIT 1",
      [userUpper]
    );

    if (!rows.length) {
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    const user = rows[0];

    if (Number(user.activo) !== 1) {
      return res.status(401).json({ message: "Usuario inactivo" });
    }

    // 👇 MUY IMPORTANTE: normalizar a string y trim por si se pegó un espacio en DB
    const hash = String(user.password_hash || "").trim();
    const ok = await bcrypt.compare(String(password), hash);

    if (!ok) {
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    const rol = String(user.rol || "").trim();
    if (!ROLES_VALIDOS.has(rol)) {
      return res.status(403).json({ message: "Rol no autorizado" });
    }

    await pool.query("UPDATE usuarios SET ultimo_login = NOW() WHERE id = ?", [user.id]);

    return res.json({ usuario: user.usuario, rol });
  } catch (e) {
    console.error("LOGIN_ERROR:", e);
    return res.status(500).json({ message: "Error interno del servidor" });
  }
});

// ✅ Arranque
const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log(`✅ Auth API corriendo en http://localhost:${PORT}`);
});



