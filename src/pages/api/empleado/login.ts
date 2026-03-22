// src/pages/api/empleado/login.ts
// POST — Login de empleado con mail_corporativo + contraseña
export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';

const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'root',
  password: import.meta.env.DB_PASSWORD || '',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

export const POST: APIRoute = async ({ request, cookies }) => {
  try {
    const { mail_corporativo, password } = await request.json();

    if (!mail_corporativo || !password) {
      return json({ success: false, message: 'Correo y contraseña son requeridos.' }, 400);
    }

    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute<any[]>(
      'SELECT id_usuario, nombre, contrasena, codigo_empresa FROM usuarios WHERE mail_corporativo = ?',
      [mail_corporativo.trim().toLowerCase()]
    );
    await conn.end();

    if (rows.length === 0) {
      return json({ success: false, message: 'Correo o contraseña incorrectos.' }, 401);
    }

    const usuario = rows[0];
    const ok = await bcrypt.compare(password, usuario.contrasena);

    if (!ok) {
      return json({ success: false, message: 'Correo o contraseña incorrectos.' }, 401);
    }

    cookies.set('empleado_session', JSON.stringify({
      id_usuario:      usuario.id_usuario,
      nombre:          usuario.nombre,
      codigo_empresa:  usuario.codigo_empresa,
    }), {
      httpOnly: true,
      secure:   import.meta.env.PROD,
      sameSite: 'lax',
      path:     '/',
      maxAge:   60 * 60 * 8,
    });

    return json({ success: true }, 200);

  } catch (err) {
    console.error('[empleado/login]', err);
    return json({ success: false, message: 'Error interno del servidor.' }, 500);
  }
};

function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}