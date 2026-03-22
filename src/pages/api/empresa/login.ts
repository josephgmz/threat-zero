// src/pages/api/empresa/login.ts
// Endpoint POST — Login de empresa
// Verifica email + contraseña contra la tabla `empresas` en MySQL

export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';

// ── Conexión a MySQL ──
// Configura estas variables en tu .env:
//   DB_HOST=localhost
//   DB_USER=operador_tz
//   DB_PASSWORD=Operador123!
//   DB_NAME=threat_zero
const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'operador_tz',
  password: import.meta.env.DB_PASSWORD || 'Operador123!',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

export const POST: APIRoute = async ({ request, cookies }) => {
  try {
    // 1. Leer body
    const body = await request.json();
    const { email, password } = body;

    // 2. Validación básica
    if (!email || !password) {
      return new Response(
        JSON.stringify({ success: false, message: 'Correo y contraseña son requeridos.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // 3. Buscar empresa por email
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute<any[]>(
      'SELECT codigo, nombre, contrasena FROM empresas WHERE email = ?',
      [email.trim().toLowerCase()]
    );
    await conn.end();

    if (rows.length === 0) {
      return new Response(
        JSON.stringify({ success: false, message: 'Correo o contraseña incorrectos.' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const empresa = rows[0];

    // 4. Comparar contraseña con hash bcrypt
    const passwordOk = await bcrypt.compare(password, empresa.contrasena);

    if (!passwordOk) {
      return new Response(
        JSON.stringify({ success: false, message: 'Correo o contraseña incorrectos.' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // 5. Crear sesión — cookie segura con el código de empresa
    // En producción considera usar JWT o una librería de sesiones completa.
    cookies.set('empresa_session', JSON.stringify({
      codigo: empresa.codigo,
      nombre: empresa.nombre,
    }), {
      httpOnly: true,
      secure:   import.meta.env.PROD,
      sameSite: 'lax',
      path:     '/',
      maxAge:   60 * 60 * 8, // 8 horas
    });

    return new Response(
      JSON.stringify({ success: true, message: 'Login exitoso.' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );

  } catch (err) {
    console.error('[login] Error:', err);
    return new Response(
      JSON.stringify({ success: false, message: 'Error interno del servidor.' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
};