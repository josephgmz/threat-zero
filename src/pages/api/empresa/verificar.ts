// ============================================================
// src/pages/api/empresa/verificar.ts
// GET — Verifica si un código de empresa existe y cuántos cupos quedan
// ============================================================
export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';

const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'root',
  password: import.meta.env.DB_PASSWORD || '',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

export const GET: APIRoute = async ({ url }) => {
  const codigo = url.searchParams.get('codigo')?.toUpperCase().trim();

  if (!codigo) {
    return json({ existe: false }, 400);
  }

  try {
    const conn = await mysql.createConnection(dbConfig);

    const [rows] = await conn.execute<any[]>(
      `SELECT e.codigo, e.nombre, e.cantidad_empleados,
              fn_total_empleados_empresa(e.codigo) AS registrados
       FROM empresas e WHERE e.codigo = ?`,
      [codigo]
    );

    await conn.end();

    if (rows.length === 0) {
      return json({ existe: false }, 200);
    }

    const emp = rows[0];
    const cupos_disponibles = Math.max(0, emp.cantidad_empleados - emp.registrados);

    return json({
      existe:           true,
      nombre:           emp.nombre,
      cupos_disponibles,
    }, 200);

  } catch (err) {
    console.error('[verificar]', err);
    return json({ existe: false }, 500);
  }
};

function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}