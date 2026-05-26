// SloanMelia — Cloudflare Pages Function
// Routes: auth, documents, achievements, colleges, scholarships, grades, coach, vault
// Bindings: DB (D1), VAULT (R2)
// Secrets: SM_EMAIL, SM_PASSWORD, JWT_SECRET, ANTHROPIC_API_KEY

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '').replace(/^\//,'').replace(/\/$/,'');

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (path === 'auth/login') return handleLogin(request, env);

  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  const payload = await verifyToken(token, env.JWT_SECRET);
  if (!payload) return json({ error: 'Unauthorized' }, 401);

  try {
    if (path === 'documents'    || path.startsWith('documents/'))    return handleDocuments(request, env, path);
    if (path === 'achievements' || path.startsWith('achievements/')) return handleAchievements(request, env, path);
    if (path === 'colleges'     || path.startsWith('colleges/'))     return handleColleges(request, env, path);
    if (path === 'scholarships' || path.startsWith('scholarships/')) return handleScholarships(request, env, path);
    if (path === 'grades'       || path.startsWith('grades/'))       return handleGrades(request, env, path);
    if (path === 'coach')         return handleCoach(request, env);
    if (path === 'vault/upload')  return handleVaultUpload(request, env);
    if (path === 'vault/download') return handleVaultDownload(request, env, url);
    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...CORS }
  });
}

async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g,'');
  const body   = btoa(JSON.stringify({ ...payload, exp: Date.now() + 86400000 * 7 })).replace(/=/g,'');
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'')}`;
}

async function verifyToken(token, secret) {
  if (!token || !secret) return false;
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const raw = atob(sig.replace(/-/g,'+').replace(/_/g,'/') + '=='.slice((sig.length + 2) % 4 || 0));
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(raw, c => c.charCodeAt(0)), enc.encode(`${header}.${body}`));
    if (!valid) return false;
    const p = JSON.parse(atob(body + '=='.slice((body.length + 2) % 4 || 0)));
    return p.exp > Date.now() ? p : false;
  } catch { return false; }
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return json({ error: 'Email and password required' }, 400);
  if (email === env.SM_EMAIL && password === env.SM_PASSWORD) {
    const token = await signToken({ userId: 'sloan-001', email }, env.JWT_SECRET);
    return json({ token, userId: 'sloan-001', email });
  }
  return json({ error: 'Invalid credentials' }, 401);
}

// ─── DOCUMENTS ────────────────────────────────────────────────────────────────

async function handleDocuments(request, env, path) {
  const db = env.DB;
  const userId = 'sloan-001';
  const id = path.split('/')[1] || null;

  if (request.method === 'GET') {
    const { results } = await db.prepare(
      'SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(userId).all();
    return json(results);
  }
  if (request.method === 'POST') {
    const b = await request.json();
    const newId = crypto.randomUUID();
    await db.prepare(
      'INSERT INTO documents (id, user_id, name, category, file_key, file_size) VALUES (?,?,?,?,?,?)'
    ).bind(newId, userId, b.name, b.category, b.file_key || null, b.file_size || null).run();
    return json({ id: newId }, 201);
  }
  if (request.method === 'DELETE' && id) {
    // Delete R2 object if file_key exists
    const { results } = await db.prepare(
      'SELECT file_key FROM documents WHERE id = ? AND user_id = ?'
    ).bind(id, userId).all();
    if (results[0]?.file_key) {
      try { await env.VAULT.delete(results[0].file_key); } catch {}
    }
    await db.prepare('DELETE FROM documents WHERE id = ? AND user_id = ?').bind(id, userId).run();
    return json({ deleted: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// ─── ACHIEVEMENTS ─────────────────────────────────────────────────────────────

async function handleAchievements(request, env, path) {
  const db = env.DB;
  const userId = 'sloan-001';
  const id = path.split('/')[1] || null;

  if (request.method === 'GET') {
    const { results } = await db.prepare(
      'SELECT * FROM achievements WHERE user_id = ? ORDER BY created_at ASC'
    ).bind(userId).all();
    return json(results);
  }
  if (request.method === 'POST') {
    const b = await request.json();
    const newId = crypto.randomUUID();
    await db.prepare(
      'INSERT INTO achievements (id, user_id, title, role, description, impact) VALUES (?,?,?,?,?,?)'
    ).bind(newId, userId, b.title, b.role || null, b.description || null, b.impact || null).run();
    return json({ id: newId }, 201);
  }
  if (request.method === 'DELETE' && id) {
    await db.prepare('DELETE FROM achievements WHERE id = ? AND user_id = ?').bind(id, userId).run();
    return json({ deleted: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// ─── COLLEGES ─────────────────────────────────────────────────────────────────

async function handleColleges(request, env, path) {
  const db = env.DB;
  const userId = 'sloan-001';
  const id = path.split('/')[1] || null;

  if (request.method === 'GET') {
    const { results } = await db.prepare(
      'SELECT * FROM college_applications WHERE user_id = ? ORDER BY created_at ASC'
    ).bind(userId).all();
    return json(results);
  }
  if (request.method === 'POST') {
    const b = await request.json();
    const newId = crypto.randomUUID();
    await db.prepare(
      'INSERT INTO college_applications (id, user_id, school_name, portal_url, status, deadline, notes) VALUES (?,?,?,?,?,?,?)'
    ).bind(newId, userId, b.school_name, b.portal_url || null, b.status || 'researching', b.deadline || null, b.notes || null).run();
    return json({ id: newId }, 201);
  }
  if (request.method === 'PUT' && id) {
    const b = await request.json();
    await db.prepare(
      'UPDATE college_applications SET school_name=?, portal_url=?, status=?, deadline=?, notes=? WHERE id=? AND user_id=?'
    ).bind(b.school_name, b.portal_url || null, b.status, b.deadline || null, b.notes || null, id, userId).run();
    return json({ updated: true });
  }
  if (request.method === 'DELETE' && id) {
    await db.prepare('DELETE FROM college_applications WHERE id = ? AND user_id = ?').bind(id, userId).run();
    return json({ deleted: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// ─── SCHOLARSHIPS ─────────────────────────────────────────────────────────────

async function handleScholarships(request, env, path) {
  const db = env.DB;
  const userId = 'sloan-001';
  const id = path.split('/')[1] || null;

  if (request.method === 'GET') {
    const { results } = await db.prepare(
      'SELECT * FROM scholarships WHERE user_id = ? ORDER BY created_at ASC'
    ).bind(userId).all();
    return json(results);
  }
  if (request.method === 'POST') {
    const b = await request.json();
    const newId = crypto.randomUUID();
    await db.prepare(
      'INSERT INTO scholarships (id, user_id, name, amount_min, amount_max, status, url, requirements) VALUES (?,?,?,?,?,?,?,?)'
    ).bind(newId, userId, b.name, b.amount_min || null, b.amount_max || null, b.status || 'researching', b.url || null, b.requirements || null).run();
    return json({ id: newId }, 201);
  }
  if (request.method === 'PUT' && id) {
    const b = await request.json();
    await db.prepare(
      'UPDATE scholarships SET name=?, amount_min=?, amount_max=?, status=?, url=?, requirements=? WHERE id=? AND user_id=?'
    ).bind(b.name, b.amount_min || null, b.amount_max || null, b.status, b.url || null, b.requirements || null, id, userId).run();
    return json({ updated: true });
  }
  if (request.method === 'DELETE' && id) {
    await db.prepare('DELETE FROM scholarships WHERE id = ? AND user_id = ?').bind(id, userId).run();
    return json({ deleted: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// ─── GRADES ───────────────────────────────────────────────────────────────────

async function handleGrades(request, env, path) {
  const db = env.DB;
  const userId = 'sloan-001';
  const id = path.split('/')[1] || null;

  if (request.method === 'GET') {
    const { results } = await db.prepare(
      'SELECT * FROM grades WHERE user_id = ? ORDER BY grade_year ASC, semester ASC'
    ).bind(userId).all();
    return json(results);
  }
  if (request.method === 'POST') {
    const b = await request.json();
    // Support bulk insert (array) or single row
    const rows = Array.isArray(b) ? b : [b];
    for (const row of rows) {
      const newId = crypto.randomUUID();
      await db.prepare(
        'INSERT INTO grades (id, user_id, course_name, grade_letter, grade_points, credit_hours, semester, grade_year, is_ap, is_honors, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
      ).bind(
        newId, userId,
        row.course_name, row.grade_letter || null, row.grade_points ?? null,
        row.credit_hours || 1, row.semester || null, row.grade_year || null,
        row.is_ap ? 1 : 0, row.is_honors ? 1 : 0, row.source || 'manual'
      ).run();
    }
    return json({ inserted: rows.length }, 201);
  }
  if (request.method === 'DELETE' && id) {
    await db.prepare('DELETE FROM grades WHERE id = ? AND user_id = ?').bind(id, userId).run();
    return json({ deleted: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// ─── VAULT (R2) ───────────────────────────────────────────────────────────────

async function handleVaultUpload(request, env) {
  const formData = await request.formData();
  const file = formData.get('file');
  const docId = formData.get('docId') || crypto.randomUUID();
  if (!file) return json({ error: 'No file provided' }, 400);

  const key = `sloan-001/${docId}/${file.name}`;
  await env.VAULT.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
  return json({ key, size: file.size }, 201);
}

async function handleVaultDownload(request, env, url) {
  const key = url.searchParams.get('key');
  if (!key) return json({ error: 'key param required' }, 400);
  const obj = await env.VAULT.get(key);
  if (!obj) return json({ error: 'File not found' }, 404);
  return new Response(obj.body, {
    headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', ...CORS }
  });
}

// ─── AI COACH ────────────────────────────────────────────────────────────────

async function handleCoach(request, env) {
  const { messages, vaultContext } = await request.json();

  const system = `You are Sloan's personal AI college application coach. Your student is:
- Name: Sloan Smith | School: Alton High School, Alton, Illinois
- GPA: 3.84 weighted / 3.55 unweighted | Target: PhD in Forensic Psychology | Graduation: May 2026
- Courses: AP Psychology, AP Statistics, CP English 4 AP, Human Body Systems PLTW 2, Biomedical Internship, Sociology, Environmental Science, Spanish 2A & 2B
- Key achievement: Patient Enrichment Program — FOUNDER (annual hospital enrichment drive, her centerpiece story)
- Also: Mu Alpha Theta, Link Crew Mentor, Salvation Army Volunteer, Church Nursery Volunteer, Math Peer Tutor
- Target schools: SIUE, University of Illinois Springfield, Missouri Baptist University, Saint Louis University
Be warm, encouraging, and specific to Sloan's goals. For essays, lead with Patient Enrichment Program.${vaultContext ? '\n\nContext:\n' + vaultContext : ''}`;

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, system, messages })
  });

  const data = await res.json();
  if (!res.ok) return json({ error: data.error?.message || 'Claude API error' }, 502);
  // Return in Anthropic format so app.html can use data.content[0].text unchanged
  return json({ content: [{ type: 'text', text: data.content?.[0]?.text || '' }] });
}
