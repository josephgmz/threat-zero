// src/pages/api/empresa/registro.ts
// Endpoint POST — Registro de nueva empresa
// Inserta en la tabla `empresas` con contraseña hasheada en bcrypt

export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';

const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'operador_tz',
  password: import.meta.env.DB_PASSWORD || 'Operador123!',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

// Reutilizamos la función del schema: fn_validar_mail
// pero también la validamos aquí en el servidor por seguridad.
function esEmailValido(correo: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);
}

export const POST: APIRoute = async ({ request, cookies }) => {
  try {
    const body = await request.json();
    const { codigo, nombre, cantidad_empleados, email, password } = body;

    // ── Validaciones ──
    if (!codigo || !nombre || !email || !password) {
      return json({ success: false, message: 'Todos los campos son obligatorios.' }, 400);
    }

    if (!/^[A-Z0-9]{1,10}$/.test(codigo)) {
      return json({ success: false, message: 'El código solo puede contener letras y números, máx. 10 caracteres.' }, 400);
    }

    if (!esEmailValido(email)) {
      return json({ success: false, message: 'El correo no tiene un formato válido.' }, 400);
    }

    if (password.length < 8) {
      return json({ success: false, message: 'La contraseña debe tener al menos 8 caracteres.' }, 400);
    }

    const conn = await mysql.createConnection(dbConfig);

    // ── Verificar que el código no esté en uso ──
    const [existeCodigo] = await conn.execute<any[]>(
      'SELECT codigo FROM empresas WHERE codigo = ?',
      [codigo]
    );
    if (existeCodigo.length > 0) {
      await conn.end();
      return json({ success: false, message: 'El código de empresa ya está registrado.' }, 409);
    }

    // ── Verificar que el email no esté en uso ──
    const [existeEmail] = await conn.execute<any[]>(
      'SELECT email FROM empresas WHERE email = ?',
      [email.trim().toLowerCase()]
    );
    if (existeEmail.length > 0) {
      await conn.end();
      return json({ success: false, message: 'Este correo ya está registrado.' }, 409);
    }

    // ── Hashear contraseña con bcrypt (10 rondas) ──
    const hash = await bcrypt.hash(password, 10);

    // ── Insertar empresa ──
    // El trigger tr_audit_new_empresa se ejecutará automáticamente en MySQL.
    await conn.execute(
      'INSERT INTO empresas (codigo, nombre, cantidad_empleados, email, contrasena) VALUES (?, ?, ?, ?, ?)',
      [codigo, nombre.trim(), cantidad_empleados || 0, email.trim().toLowerCase(), hash]
    );

    await conn.end();

    // ── Crear sesión ──
    cookies.set('empresa_session', JSON.stringify({ codigo, nombre: nombre.trim() }), {
      httpOnly: true,
      secure:   import.meta.env.PROD,
      sameSite: 'lax',
      path:     '/',
      maxAge:   60 * 60 * 8,
    });

    return json({ success: true, message: 'Empresa registrada exitosamente.' }, 201);

  } catch (err: any) {
    console.error('[registro] Error:', err);

    // Error de clave duplicada de MySQL (código 1062)
    if (err?.code === 'ER_DUP_ENTRY') {
      return json({ success: false, message: 'El código o correo ya está registrado.' }, 409);
    }

    return json({ success: false, message: 'Error interno del servidor.' }, 500);
  }
};

// Helper para no repetir new Response(...)
function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}