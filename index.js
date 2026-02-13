const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(express.json());

// Render está detrás de proxy (importante para headers/https)
app.set("trust proxy", 1);

// ===== LOGGING INICIAL =====
console.log("🚀 Iniciando servidor...");
console.log("🔍 NODE_ENV:", process.env.NODE_ENV || "development");
console.log("🔍 DATABASE_URL presente:", !!process.env.DATABASE_URL);
console.log("🔍 FRONTEND_ORIGIN presente:", !!process.env.FRONTEND_ORIGIN);

// ===== CORS =====
const allowedOrigins = new Set(
  [
    process.env.FRONTEND_ORIGIN,
    "https://fnc-coffee-gateway-np9a.vercel.app",
    "http://localhost:5173",
    "http://localhost:5175",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5175",
  ].filter(Boolean)
);

console.log("🌐 CORS habilitado para:", Array.from(allowedOrigins));

const corsOptions = {
  origin: (origin, cb) => {
    // Permitir requests sin origin (Postman, curl, server-to-server)
    if (!origin) {
      console.log("✅ Request sin origin permitido (Postman/curl)");
      return cb(null, true);
    }
    
    if (allowedOrigins.has(origin)) {
      console.log("✅ CORS permitido para:", origin);
      return cb(null, true);
    }
    
    console.warn("❌ CORS bloqueado para:", origin);
    return cb(new Error(`CORS bloqueado para: ${origin}`));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ===== VERIFICACIÓN DATABASE_URL =====
if (!process.env.DATABASE_URL) {
  console.error("❌ FATAL: Falta DATABASE_URL en variables de entorno");
  console.error("📝 Configura DATABASE_URL en Render → Environment");
  process.exit(1);
}

// Mostrar solo primeros caracteres por seguridad
const dbUrlPreview = process.env.DATABASE_URL.substring(0, 30) + "...";
console.log("🔗 DATABASE_URL detectada:", dbUrlPreview);

// ===== POOL DE CONEXIONES =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { 
    rejectUnauthorized: false 
  },
  connectionTimeoutMillis: 10000, // 10 segundos timeout
  idleTimeoutMillis: 30000,       // Desconectar conexiones idle después de 30s
  max: 10,                        // Máximo 10 conexiones simultáneas
});

// Manejo de errores del pool
pool.on("error", (err) => {
  console.error("❌ Error inesperado en pool de BD:", err);
});

// Test de conexión al iniciar
pool.query("SELECT NOW() as tiempo, version() as version", (err, res) => {
  if (err) {
    console.error("❌ Error conectando a BD:", err.message);
    console.error("💡 Verifica DATABASE_URL en Render Environment");
  } else {
    console.log("✅ Conectado exitosamente a PostgreSQL");
    console.log("⏰ Timestamp DB:", res.rows[0].tiempo);
    console.log("📊 Version:", res.rows[0].version.split(" ").slice(0, 2).join(" "));
  }
});

// ===== ROLES VÁLIDOS =====
const ROLES_VALIDOS = new Set(["Director", "CoordProyectos", "Financiera"]);
console.log("🔐 Roles válidos:", Array.from(ROLES_VALIDOS));

// ===== MIDDLEWARE DE LOGGING =====
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`📨 [${timestamp}] ${req.method} ${req.path} - Origin: ${req.headers.origin || "N/A"}`);
  next();
});

// ===== ENDPOINTS =====

// Health check
app.get("/", (_req, res) => {
  res.json({ 
    service: "FNC Auth API",
    status: "running",
    timestamp: new Date().toISOString()
  });
});

app.get("/health", async (_req, res) => {
  try {
    const result = await pool.query("SELECT NOW() as tiempo");
    res.json({ 
      ok: true, 
      db: true,
      timestamp: result.rows[0].tiempo 
    });
  } catch (e) {
    console.error("❌ HEALTH_ERROR:", e.message);
    res.status(500).json({ 
      ok: false, 
      db: false, 
      error: "db_error",
      message: e.message 
    });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const requestId = Date.now();
  console.log(`\n🔑 [${requestId}] === INICIO LOGIN ===`);
  
  try {
    const { usuario, password } = req.body || {};
    console.log(`[${requestId}] Usuario recibido:`, usuario || "N/A");

    // Validación de entrada
    if (!usuario || !password) {
      console.log(`[${requestId}] ❌ Faltan credenciales`);
      return res.status(400).json({ message: "Faltan credenciales" });
    }

    const userUpper = String(usuario).toUpperCase().trim();
    console.log(`[${requestId}] 🔍 Buscando usuario: "${userUpper}"`);

    // Buscar usuario en BD
    const { rows } = await pool.query(
      `SELECT id, usuario, password_hash, rol, activo
       FROM public.usuarios
       WHERE usuario = $1
       LIMIT 1`,
      [userUpper]
    );

    console.log(`[${requestId}] 📊 Usuarios encontrados:`, rows.length);

    if (!rows.length) {
      console.log(`[${requestId}] ❌ Usuario no existe en BD`);
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    const user = rows[0];
    console.log(`[${requestId}] 👤 Usuario encontrado:`, {
      id: user.id,
      usuario: user.usuario,
      rol: user.rol,
      activo: user.activo,
      hasHash: !!user.password_hash
    });

    // Verificar si está activo
    if (user.activo !== true) {
      console.log(`[${requestId}] ❌ Usuario inactivo`);
      return res.status(401).json({ message: "Usuario inactivo" });
    }

    // Verificar password
    const hash = String(user.password_hash || "").trim();
    console.log(`[${requestId}] 🔐 Verificando password... (hash length: ${hash.length})`);
    
    const passwordMatch = await bcrypt.compare(String(password), hash);
    console.log(`[${requestId}] 🔐 Password match:`, passwordMatch);

    if (!passwordMatch) {
      console.log(`[${requestId}] ❌ Password incorrecto`);
      return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
    }

    // Verificar rol
    const rol = String(user.rol || "").trim();
    console.log(`[${requestId}] 🎭 Verificando rol: "${rol}"`);
    
    if (!ROLES_VALIDOS.has(rol)) {
      console.log(`[${requestId}] ❌ Rol no autorizado: "${rol}"`);
      return res.status(403).json({ message: "Rol no autorizado" });
    }

    // Actualizar último login
    console.log(`[${requestId}] 📝 Actualizando ultimo_login...`);
    await pool.query(
      "UPDATE public.usuarios SET ultimo_login = NOW() WHERE id = $1",
      [user.id]
    );

    console.log(`[${requestId}] ✅ LOGIN EXITOSO - Usuario: ${user.usuario}, Rol: ${rol}`);
    console.log(`[${requestId}] === FIN LOGIN ===\n`);
    
    return res.json({ 
      usuario: user.usuario, 
      rol: rol 
    });

  } catch (e) {
    console.error(`[${requestId}] 💥 LOGIN_ERROR:`, e.message);
    console.error(`[${requestId}] Stack:`, e.stack);
    console.log(`[${requestId}] === FIN LOGIN (CON ERROR) ===\n`);
    
    return res.status(500).json({ 
      message: "Error interno del servidor",
      error: process.env.NODE_ENV === "development" ? e.message : undefined
    });
  }
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  console.log(`❌ 404 - Ruta no encontrada: ${req.method} ${req.path}`);
  res.status(404).json({ 
    error: "Ruta no encontrada",
    path: req.path 
  });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error("💥 Error global:", err.message);
  res.status(500).json({ 
    message: "Error del servidor",
    error: process.env.NODE_ENV === "development" ? err.message : undefined
  });
});

// ===== ARRANQUE DEL SERVIDOR =====
const PORT = Number(process.env.PORT || 3001);

app.listen(PORT, () => {
  console.log("\n" + "=".repeat(50));
  console.log(`✅ Auth API corriendo en puerto ${PORT}`);
  console.log(`🌍 Endpoints disponibles:`);
  console.log(`   - GET  /          → Info del servicio`);
  console.log(`   - GET  /health    → Health check`);
  console.log(`   - POST /login     → Autenticación`);
  console.log("=".repeat(50) + "\n");
});

// Manejo de cierre graceful
process.on("SIGTERM", async () => {
  console.log("⚠️ SIGTERM recibido, cerrando servidor...");
  await pool.end();
  console.log("✅ Pool de BD cerrado");
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("\n⚠️ SIGINT recibido, cerrando servidor...");
  await pool.end();
  console.log("✅ Pool de BD cerrado");
  process.exit(0);
});