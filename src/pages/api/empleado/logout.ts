// src/pages/api/empleado/logout.ts
// POST — Cierra la sesión del empleado borrando la cookie
export const prerender = false;

import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ cookies }) => {
  cookies.delete('empleado_session', { path: '/' });
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};

// ============================================================
// src/pages/api/empresa/logout.ts  (mismo patrón para empresa)
// Copia este archivo a api/empresa/logout.ts y cambia:
//   cookies.delete('empleado_session' → 'empresa_session')
// ============================================================