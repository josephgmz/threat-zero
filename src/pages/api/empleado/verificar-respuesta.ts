// src/pages/api/empleado/verificar-respuesta.ts
// GET — Verifica si una respuesta es correcta y devuelve la id correcta
// Se consulta en tiempo real para no exponer es_correcta en el HTML
export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';

const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'root',
  password: import.meta.env.DB_PASSWORD || '',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

export const GET: APIRoute = async ({ url, cookies }) => {
  // Verificar sesión
  const session = cookies.get('empleado_session');
  if (!session?.value) {
    return json({ error: 'No autorizado' }, 401);
  }

  const idRespuesta = parseInt(url.searchParams.get('id_respuesta') || '0');
  if (!idRespuesta) return json({ error: 'ID inválido' }, 400);

  try {
    const conn = await mysql.createConnection(dbConfig);

    // Obtener si la respuesta seleccionada es correcta
    const [rows] = await conn.execute<any[]>(
      'SELECT es_correcta, id_pregunta FROM respuestas WHERE id_respuesta = ?',
      [idRespuesta]
    );

    if (rows.length === 0) {
      await conn.end();
      return json({ error: 'Respuesta no encontrada' }, 404);
    }

    const esCorrecta   = rows[0].es_correcta === 1 || rows[0].es_correcta === true;
    const idPregunta   = rows[0].id_pregunta;

    // Obtener el ID de la respuesta correcta para resaltarla en el cliente
    const [correctaRows] = await conn.execute<any[]>(
      'SELECT id_respuesta FROM respuestas WHERE id_pregunta = ? AND es_correcta = TRUE LIMIT 1',
      [idPregunta]
    );

    await conn.end();

    return json({
      correcta:    esCorrecta,
      id_correcta: correctaRows[0]?.id_respuesta ?? null,
    }, 200);

  } catch (err) {
    console.error('[verificar-respuesta]', err);
    return json({ error: 'Error interno' }, 500);
  }
};

function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}