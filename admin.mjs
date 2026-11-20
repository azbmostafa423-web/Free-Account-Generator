import { timingSafeEqual } from 'node:crypto';
import { getDatabase } from '@netlify/database';

// Returns 'ok' | 'denied' | 'unconfigured'
function authorize(request) {
  // trim() protects against accidental spaces/newlines when the variable is pasted in Netlify
  const expected = (process.env.ADMIN_PASSWORD || 'M0st@f@_Pr0').trim();
  if (!expected) return 'unconfigured';
  let supplied = request.headers.get('x-admin-password') || '';
  try { supplied = decodeURIComponent(supplied); } catch { /* keep raw value */ }
  supplied = supplied.trim();
  if (!supplied) return 'denied';
  const a = Buffer.from(expected);
  const b = Buffer.from(supplied);
  return a.length === b.length && timingSafeEqual(a, b) ? 'ok' : 'denied';
}

function jsonError(message, status) {
  return Response.json({ error: message }, { status });
}

export default async (request) => {
  const auth = authorize(request);
  if (auth === 'unconfigured') {
    console.error('ADMIN_PASSWORD environment variable is not set (redeploy after adding it).');
    return jsonError('ADMIN_PASSWORD is not configured on the server', 500);
  }
  if (auth !== 'ok') return jsonError('Unauthorized', 401);

  try {
    const db = getDatabase();

    if (request.method === 'GET') {
      const rows = await db.sql`
        SELECT email, password
        FROM mc_accounts
        WHERE claimed_at IS NULL
        ORDER BY id ASC
      `;
      return Response.json({ accounts: rows.map(row => `${row.email}:${row.password}`) });
    }

    if (request.method === 'PUT') {
      let body;
      try { body = await request.json(); } catch { return jsonError('Invalid JSON', 400); }
      if (!Array.isArray(body.accounts) || body.accounts.length > 5000) {
        return jsonError('Invalid accounts list (maximum 5000)', 400);
      }

      const accounts = [];
      for (const raw of body.accounts) {
        if (typeof raw !== 'string') continue;
        const line = raw.trim();
        const splitAt = line.indexOf(':');
        if (splitAt <= 0 || splitAt === line.length - 1) continue;
        const email = line.slice(0, splitAt).trim();
        const password = line.slice(splitAt + 1).trim();
        if (!email || !password || email.length > 320 || password.length > 1024) continue;
        accounts.push([email, password]);
      }

      const client = await db.pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM mc_accounts WHERE claimed_at IS NULL');
        for (const [email, password] of accounts) {
          await client.query(
            'INSERT INTO mc_accounts (email, password) VALUES ($1, $2)',
            [email, password]
          );
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      return Response.json({ ok: true, saved: accounts.length });
    }

    return jsonError('Method not allowed', 405);
  } catch (error) {
    console.error('Admin API error:', error);
    return jsonError('Server error', 500);
  }
};

export const config = { path: '/api/admin' };
