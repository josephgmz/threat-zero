// src/pages/api/empleado/guardar-test.ts
// POST — Guarda el resultado del test usando sp_registrar_diagnostico_completo
export const prerender = false;

import type { APIRoute } from 'astro';
import mysql from 'mysql2/promise';

const dbConfig = {
  host:     import.meta.env.DB_HOST     || 'localhost',
  user:     import.meta.env.DB_USER     || 'root',
  password: import.meta.env.DB_PASSWORD || '',
  database: import.meta.env.DB_NAME     || 'threat_zero',
};

export const POST: APIRoute = async ({ request, cookies }) => {
  // Verificar sesión
  const session = cookies.get('empleado_session');
  if (!session?.value) return json({ success: false, message: 'No autorizado' }, 401);

  try {
    const sesion   = JSON.parse(session.value);
    const { puntaje } = await request.json();

    if (puntaje === undefined || puntaje < 0 || puntaje > 100) {
      return json({ success: false, message: 'Puntaje inválido' }, 400);
    }

    const conn = await mysql.createConnection(dbConfig);

    // Verificar que no haya hecho el test antes
    const [yaHizo] = await conn.execute<any[]>(
      'SELECT id_diagnostico FROM diagnostico WHERE id_usuario = ? LIMIT 1',
      [sesion.id_usuario]
    );

    if (yaHizo.length > 0) {
      await conn.end();
      return json({ success: false, message: 'Ya completaste el test anteriormente.' }, 409);
    }

    // Determinar sugerencia según puntaje usando fn_nivel_riesgo del schema
    const [nivelRows] = await conn.execute<any[]>(
      'SELECT fn_nivel_riesgo(?) AS nivel', [puntaje]
    );
    const nivel = nivelRows[0]?.nivel || 'alto';

    // Obtener una sugerencia del nivel correspondiente
    const [sugRows] = await conn.execute<any[]>(
      'SELECT id_sugerencia FROM sugerencias WHERE nivel_riesgo = ? ORDER BY RAND() LIMIT 1',
      [nivel]
    );

    // Si no hay sugerencias del nivel, usar cualquiera
    let idSugerencia = sugRows[0]?.id_sugerencia;
    if (!idSugerencia) {
      const [anySug] = await conn.execute<any[]>(
        'SELECT id_sugerencia FROM sugerencias LIMIT 1'
      );
      idSugerencia = anySug[0]?.id_sugerencia || 1;
    }

    // Usar el stored procedure del schema para registrar el diagnóstico
    // sp_registrar_diagnostico_completo(id_usuario, puntaje, id_sugerencia)
    await conn.execute(
      'CALL sp_registrar_diagnostico_completo(?, ?, ?)',
      [sesion.id_usuario, puntaje, idSugerencia]
    );

    await conn.end();

    return json({ success: true, puntaje, nivel }, 200);

  } catch (err: any) {
    console.error('[guardar-test]', err);
    return json({ success: false, message: 'Error al guardar el diagnóstico.' }, 500);
  }
};

function json(data: object, status: number) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}