// Earth's Last Exam sign-up backend.
//   POST /api/signup            public; the landing-page form posts here
//   GET  /admin                 password-protected dashboard (the "CMS")
//   GET  /admin/api/signups     JSON list for the dashboard
//   GET  /admin/export.csv      CSV download
//   PATCH/DELETE /admin/api/signups/:id
// Bindings: DB (D1), secrets ADMIN_PASSWORD and SESSION_SECRET, var ALLOWED_ORIGINS (comma-separated).

const enc = new TextEncoder();
const SESSION_HOURS = 12;
const MAX_SIGNUPS_PER_IP_PER_HOUR = 10;

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra } });

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return allowed.includes(origin)
    ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' }
    : { 'Vary': 'Origin' };
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Compare through HMAC so length differences do not leak and the comparison is constant time.
async function safeEqual(a, b, secret) {
  const [x, y] = await Promise.all([hmac(secret, a), hmac(secret, b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

async function makeSession(env) {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  return `${exp}.${await hmac(env.SESSION_SECRET, 'admin:' + exp)}`;
}

async function isAdmin(request, env) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)ele_admin=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(env.SESSION_SECRET, 'admin:' + exp), env.SESSION_SECRET);
}

const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

async function handleSignup(request, env) {
  const cors = corsHeaders(request, env);
  let body;
  try { body = await request.json(); } catch { return json({ success: false, error: 'Invalid request.' }, 400, cors); }

  // Honeypot: bots fill the hidden field. Pretend success so they do not retry.
  if (clean(body.website, 50)) return json({ success: true, message: "You're on the list." }, 200, cors);

  const name = clean(body.name, 120);
  const email = clean(body.email, 200).toLowerCase();
  const affiliation = clean(body.affiliation, 200);
  let expertise = clean(body.expertise, 80);
  const expertiseOther = clean(body.expertise_other, 120);
  if (!name || !email) return json({ success: false, error: 'Please enter your name and email.' }, 400, cors);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ success: false, error: 'That email address does not look right.' }, 400, cors);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = (await sha256(ip + ':' + env.SESSION_SECRET)).slice(0, 24);
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM signups WHERE ip_hash = ? AND updated_at > datetime(\'now\', \'-1 hour\')').bind(ipHash).first();
  if (recent && recent.n >= MAX_SIGNUPS_PER_IP_PER_HOUR) return json({ success: false, error: 'Too many sign-ups from this network. Please try again later.' }, 429, cors);

  // Same email signing up again updates their details instead of creating a duplicate.
  await env.DB.prepare(
    `INSERT INTO signups (name, email, affiliation, expertise, expertise_other, ip_hash, source)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(email) DO UPDATE SET name = excluded.name, affiliation = excluded.affiliation,
       expertise = excluded.expertise, expertise_other = excluded.expertise_other, updated_at = datetime('now')`
  ).bind(name, email, affiliation, expertise, expertiseOther, ipHash, clean(request.headers.get('Origin'), 100)).run();

  return json({ success: true, message: "You're on the list. We'll email you when submissions open." }, 200, cors);
}

const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // stop spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request, env) });

    if (path === '/api/signup' && request.method === 'POST') return handleSignup(request, env);

    if (path === '/' ) return new Response('Earth\'s Last Exam sign-up service.', { headers: { 'Content-Type': 'text/plain' } });

    if (path === '/admin/login' && request.method === 'POST') {
      const form = await request.formData();
      const ok = await safeEqual(String(form.get('password') || ''), env.ADMIN_PASSWORD, env.SESSION_SECRET);
      if (!ok) { await new Promise((r) => setTimeout(r, 800)); return new Response(loginPage('Incorrect password.'), { status: 401, headers: pageHeaders() }); }
      return new Response(null, { status: 303, headers: { Location: '/admin', 'Set-Cookie': `ele_admin=${await makeSession(env)}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}` } });
    }

    if (path === '/admin/logout') {
      return new Response(null, { status: 303, headers: { Location: '/admin', 'Set-Cookie': 'ele_admin=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0' } });
    }

    if (path === '/admin' || path.startsWith('/admin/')) {
      if (!(await isAdmin(request, env))) {
        if (path === '/admin') return new Response(loginPage(), { headers: pageHeaders() });
        return json({ error: 'Not signed in.' }, 401);
      }
      if (path === '/admin') return new Response(DASHBOARD, { headers: pageHeaders() });

      if (path === '/admin/api/signups' && request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, name, email, affiliation, expertise, expertise_other, status, notes, created_at, updated_at FROM signups ORDER BY created_at DESC').all();
        return json({ signups: results });
      }

      if (path === '/admin/export.csv') {
        const { results } = await env.DB.prepare('SELECT name, email, affiliation, expertise, expertise_other, status, notes, created_at FROM signups ORDER BY created_at DESC').all();
        const head = ['Name', 'Email', 'Affiliation', 'Expertise', 'Expertise (other)', 'Status', 'Notes', 'Signed up (UTC)'];
        const rows = results.map((r) => [r.name, r.email, r.affiliation, r.expertise, r.expertise_other, r.status, r.notes, r.created_at].map(csvCell).join(','));
        return new Response([head.map(csvCell).join(','), ...rows].join('\n'), {
          headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="earths-last-exam-signups-${new Date().toISOString().slice(0, 10)}.csv"`, 'Cache-Control': 'no-store' },
        });
      }

      const m = path.match(/^\/admin\/api\/signups\/(\d+)$/);
      if (m) {
        // Custom header is a CSRF guard on top of the SameSite=Strict cookie.
        if (request.headers.get('X-Requested-With') !== 'ele-admin') return json({ error: 'Bad request.' }, 400);
        if (request.method === 'DELETE') {
          await env.DB.prepare('DELETE FROM signups WHERE id = ?').bind(Number(m[1])).run();
          return json({ ok: true });
        }
        if (request.method === 'PATCH') {
          const b = await request.json().catch(() => ({}));
          const status = ['new', 'contacted', 'submitted'].includes(b.status) ? b.status : 'new';
          await env.DB.prepare('UPDATE signups SET status = ?, notes = ? WHERE id = ?').bind(status, clean(b.notes, 500), Number(m[1])).run();
          return json({ ok: true });
        }
      }
    }
    return new Response('Not found', { status: 404 });
  },
};

const pageHeaders = () => ({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex', 'Referrer-Policy': 'no-referrer' });

const STYLE = `
*{box-sizing:border-box}body{margin:0;background:#00181d;color:#e8f4f5;font:15px/1.5 Inter,-apple-system,Segoe UI,sans-serif}
a{color:#7EBEC5}h1{font:600 1.35rem 'Space Grotesk',Inter,sans-serif;margin:0}
.btn{background:#166A7C;color:#fff;border:1px solid #7EBEC5;border-radius:8px;padding:.5rem .9rem;font:600 .85rem inherit;cursor:pointer;text-decoration:none;display:inline-block}
.btn:hover{background:#7EBEC5;color:#00222a}.btn.sm{padding:.25rem .6rem;font-size:.78rem}.btn.danger{border-color:#f87171;background:transparent;color:#f87171}.btn.danger:hover{background:#f87171;color:#1a0000}
input,select{background:#001a20;border:1px solid #166A7C;border-radius:8px;color:#fff;padding:.5rem .7rem;font:inherit}`;

function loginPage(error = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Sign in | Earth's Last Exam admin</title><style>${STYLE}
form{max-width:340px;margin:18vh auto;padding:2rem;background:#00252d;border:1px solid #166A7C;border-radius:16px;display:grid;gap:1rem}.err{color:#f87171;min-height:1.2em;margin:0}</style></head>
<body><form method="post" action="/admin/login"><h1>Earth's Last Exam<br><span style="font-weight:400;color:#92D2D2;font-size:.95rem">Sign-up admin</span></h1>
<input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required><p class="err">${error}</p><button class="btn" type="submit">Sign in</button></form></body></html>`;
}

const DASHBOARD = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Sign-ups | Earth's Last Exam admin</title><style>${STYLE}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:1rem 1.5rem;border-bottom:1px solid #166A7C;flex-wrap:wrap}
main{padding:1.5rem;max-width:1300px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{background:#00252d;border:1px solid #166A7C;border-radius:12px;padding:1rem}.stat b{display:block;font:600 1.9rem 'Space Grotesk',sans-serif;color:#A5FFB4}.stat span{color:#94a3b8;font-size:.82rem}
.bars{background:#00252d;border:1px solid #166A7C;border-radius:12px;padding:1rem 1.2rem;margin-bottom:1.5rem}.bars h2{font-size:.85rem;margin:0 0 .7rem;color:#92D2D2;letter-spacing:.06em;text-transform:uppercase}
.bar{display:grid;grid-template-columns:230px 1fr 34px;gap:.7rem;align-items:center;margin:.3rem 0;font-size:.85rem}.bar i{display:block;height:9px;background:#7EBEC5;border-radius:5px;min-width:3px}
.tools{display:flex;gap:.7rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}.tools input{flex:1;min-width:200px}
.wrap{overflow-x:auto;border:1px solid #166A7C;border-radius:12px}table{border-collapse:collapse;width:100%;min-width:900px}
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid rgba(22,106,124,.45);vertical-align:top;font-size:.86rem}th{background:#00252d;color:#92D2D2;font-size:.74rem;letter-spacing:.07em;text-transform:uppercase;cursor:pointer;white-space:nowrap;user-select:none}
tr:last-child td{border-bottom:0}td.n{white-space:nowrap;color:#94a3b8}.empty{padding:2rem;text-align:center;color:#94a3b8}
@media(max-width:640px){.bar{grid-template-columns:120px 1fr 28px}}</style></head>
<body><header><h1>Earth's Last Exam <span style="font-weight:400;color:#92D2D2">&middot; sign-ups</span></h1><div><a class="btn" href="/admin/export.csv">Download CSV</a> <a class="btn" href="/admin/logout">Sign out</a></div></header>
<main><div class="stats" id="stats"></div><div class="bars" id="bars"></div>
<div class="tools"><input id="q" type="search" placeholder="Search name, email, affiliation, notes..."><select id="fx"><option value="">All fields</option></select><select id="fs"><option value="">Any status</option><option>new</option><option>contacted</option><option>submitted</option></select></div>
<div class="wrap"><table><thead><tr><th data-k="created_at">Signed up &#8645;</th><th data-k="name">Name &#8645;</th><th data-k="email">Email &#8645;</th><th data-k="affiliation">Affiliation &#8645;</th><th data-k="expertise">Expertise &#8645;</th><th data-k="status">Status</th><th>Notes</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></main>
<script>
const H={'X-Requested-With':'ele-admin','Content-Type':'application/json'};
let all=[],sortK='created_at',sortDir=-1;
const $=id=>document.getElementById(id);
const el=(t,props={},...kids)=>{const e=document.createElement(t);Object.assign(e,props);kids.forEach(k=>e.append(k));return e};
const field=r=>r.expertise==='Other'&&r.expertise_other?'Other: '+r.expertise_other:r.expertise;
async function load(){
  const res=await fetch('/admin/api/signups');if(res.status===401){location.reload();return}
  all=(await res.json()).signups;
  all.forEach(r=>{r.expertise=r.expertise||'Not given'});
  const fields=[...new Set(all.map(r=>r.expertise))].sort();
  $('fx').replaceChildren(el('option',{value:'',textContent:'All fields'}),...fields.map(f=>el('option',{value:f,textContent:f})));
  render();
}
function render(){
  const q=$('q').value.toLowerCase(),fx=$('fx').value,fs=$('fs').value;
  const now=Date.now(),week=all.filter(r=>now-new Date(r.created_at.replace(' ','T')+'Z')<7*864e5).length;
  $('stats').replaceChildren(...[[all.length,'total sign-ups'],[week,'in the last 7 days'],[new Set(all.filter(r=>r.affiliation).map(r=>r.affiliation.toLowerCase())).size,'distinct affiliations'],[all.filter(r=>r.status==='new').length,'not yet contacted']].map(([n,l])=>el('div',{className:'stat'},el('b',{textContent:n}),el('span',{textContent:l}))));
  const counts={};all.forEach(r=>counts[r.expertise]=(counts[r.expertise]||0)+1);
  const max=Math.max(1,...Object.values(counts));
  $('bars').replaceChildren(el('h2',{textContent:'Sign-ups by field'}),...Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([k,v])=>{const i=el('i');i.style.width=(v/max*100)+'%';return el('div',{className:'bar'},el('span',{textContent:k}),el('div',{},i),el('span',{textContent:v}))}));
  let rows=all.filter(r=>(!fx||r.expertise===fx)&&(!fs||r.status===fs)&&(!q||[r.name,r.email,r.affiliation,field(r),r.notes].join(' ').toLowerCase().includes(q)));
  rows.sort((a,b)=>String(a[sortK]).localeCompare(String(b[sortK]))*sortDir);
  const tb=$('rows');
  if(!rows.length){tb.replaceChildren(el('tr',{},el('td',{colSpan:8,className:'empty',textContent:all.length?'No matches.':'No sign-ups yet.'})));return}
  tb.replaceChildren(...rows.map(r=>{
    const st=el('select',{},...['new','contacted','submitted'].map(s=>el('option',{value:s,textContent:s,selected:s===r.status})));
    const nt=el('input',{value:r.notes||'',maxLength:500,placeholder:'Add note'});
    const save=async()=>{await fetch('/admin/api/signups/'+r.id,{method:'PATCH',headers:H,body:JSON.stringify({status:st.value,notes:nt.value})});r.status=st.value;r.notes=nt.value};
    st.onchange=async()=>{await save();render()};nt.onchange=save;
    const del=el('button',{className:'btn sm danger',textContent:'Delete',onclick:async()=>{if(!confirm('Delete '+r.name+' ('+r.email+')? This cannot be undone.'))return;await fetch('/admin/api/signups/'+r.id,{method:'DELETE',headers:H});all=all.filter(x=>x.id!==r.id);render()}});
    return el('tr',{},el('td',{className:'n',textContent:r.created_at.slice(0,16)}),el('td',{textContent:r.name}),el('td',{},el('a',{href:'mailto:'+r.email,textContent:r.email})),el('td',{textContent:r.affiliation||'—'}),el('td',{textContent:field(r)}),el('td',{},st),el('td',{},nt),el('td',{},del));
  }));
}
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{sortDir=sortK===th.dataset.k?-sortDir:1;sortK=th.dataset.k;render()});
['q','fx','fs'].forEach(i=>$(i).addEventListener('input',render));
load();
</script></body></html>`;
