// src/pages/api/empleado/registro.ts
// POST — Registro de empleado con validación de cupos disponibles
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
    const { codigo_empresa, nombre, mail_corporativo, telefono, password } = await request.json();

    // Validaciones básicas
    if (!codigo_empresa || !nombre || !mail_corporativo || !password) {
      return json({ success: false, message: 'Todos los campos obligatorios deben estar completos.' }, 400);
    }

    if (password.length < 8) {
      return json({ success: false, message: 'La contraseña debe tener al menos 8 caracteres.' }, 400);
    }

    const conn = await mysql.createConnection(dbConfig);

    // 1. Verificar que la empresa existe
    const [empresaRows] = await conn.execute<any[]>(
      'SELECT codigo, cantidad_empleados FROM empresas WHERE codigo = ?',
      [codigo_empresa.toUpperCase()]
    );

    if (empresaRows.length === 0) {
      await conn.end();
      return json({ success: false, message: 'El código de empresa no es válido.' }, 404);
    }

    // 2. Verificar cupos disponibles usando la función del schema
    const [cuposRows] = await conn.execute<any[]>(
      'SELECT fn_total_empleados_empresa(?) AS registrados, ? AS limite',
      [codigo_empresa, empresaRows[0].cantidad_empleados]
    );

    const registrados = cuposRows[0].registrados;
    const limite      = cuposRows[0].limite;

    if (registrados >= limite) {
      await conn.end();
      return json({
        success: false,
        message: 'Esta empresa ya alcanzó su límite de empleados registrados.',
      }, 409);
    }

    // 3. Verificar que el correo no esté ya registrado
    const [mailRows] = await conn.execute<any[]>(
      'SELECT id_usuario FROM usuarios WHERE mail_corporativo = ?',
      [mail_corporativo.trim().toLowerCase()]
    );

    if (mailRows.length > 0) {
      await conn.end();
      return json({ success: false, message: 'Este correo ya está registrado.' }, 409);
    }

    // 4. Hashear contraseña y registrar
    // El trigger tr_audit_new_user se ejecuta automáticamente en MySQL
    const hash = await bcrypt.hash(password, 10);

    await conn.execute(
      'INSERT INTO usuarios (nombre, mail_corporativo, telefono, contrasena, codigo_empresa) VALUES (?, ?, ?, ?, ?)',
      [
        nombre.trim(),
        mail_corporativo.trim().toLowerCase(),
        telefono?.trim() || null,
        hash,
        codigo_empresa.toUpperCase(),
      ]
    );

    // 5. Obtener el ID recién creado para la sesión
    const [newUser] = await conn.execute<any[]>(
      'SELECT id_usuario FROM usuarios WHERE mail_corporativo = ?',
      [mail_corporativo.trim().toLowerCase()]
    );

    await conn.end();

    // 6. Crear sesión
    cookies.set('empleado_session', JSON.stringify({
      id_usuario:     newUser[0].id_usuario,
      nombre:         nombre.trim(),
      codigo_empresa: codigo_empresa.toUpperCase(),
    }), {
      httpOnly: true,
      secure:   import.meta.env.PROD,
      sameSite: 'lax',
      path:     '/',
      maxAge:   60 * 60 * 8,
    });

    return json({ success: true, message: 'Registro exitoso.' }, 201);

  } catch (err: any) {
    console.error('[empleado/registro]', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return json({ success: false, message: 'Este correo ya está registrado.' }, 409);
    }

    return json({ success: false, message: 'Error interno del servidor.' }, 500);
  }
};

function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}