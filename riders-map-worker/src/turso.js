/* Turso (libSQL HTTP pipeline) adapter that mimics the D1 binding surface this worker uses:
   prepare(sql).bind(...args).{run,all,first} and batch([stmt,...]) returning
   { success, results?, meta: { rows_read, rows_written, changes, duration } }.
   Staging-only (27 Nov, Micheal 24282605): lets team-mh-staging run the notification
   workload on Turso while live team-mh stays on D1. No npm deps - plain fetch.
   Docs: POST {url}/v2/pipeline  { requests: [{type:'execute', stmt:{sql,args}}, {type:'close'}] }
*/

function tArg(v) {
  if (v === null || v === undefined) return { type: 'null', value: null };
  if (typeof v === 'number') {
    if (Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER) return { type: 'integer', value: String(v) };
    return { type: 'float', value: v };
  }
  if (typeof v === 'bigint') return { type: 'integer', value: v.toString() };
  if (typeof v === 'boolean') return { type: 'integer', value: v ? '1' : '0' };
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
    const bytes = v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
    return { type: 'blob', value: btoa(bin) };
  }
  return { type: 'text', value: String(v) };
}

function cellVal(c) {
  if (c == null || c.type === 'null') return null;
  if (c.type === 'integer') { const n = Number(c.value); return Number.isSafeInteger(n) ? n : c.value; }
  if (c.type === 'float') return Number(c.value);
  if (c.type === 'blob') return c.value; // base64 string; this worker stores no blobs in the moved tables
  return c.value;
}

export function makeTursoDb(url, token) {
  const base = String(url || '').replace(/\/$/, '').replace(/^libsql:\/\//, 'https://');

  async function pipeline(stmts) {
    const requests = stmts.map(s => ({
      type: 'execute',
      stmt: s.args && s.args.length ? { sql: s.sql, args: s.args.map(tArg) } : { sql: s.sql },
    }));
    requests.push({ type: 'close' });
    const resp = await fetch(base + '/v2/pipeline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ requests }),
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || !Array.isArray(data.results)) {
      const msg = data && data.error ? (data.error.message || data.error) : 'HTTP ' + resp.status;
      throw new Error('turso pipeline: ' + msg);
    }
    return data.results.map((r, i) => {
      if (r.type === 'error') {
        const msg = r.error && r.error.message ? r.error.message : 'unknown';
        throw new Error('turso stmt ' + i + ': ' + msg);
      }
      const res = (r.response && r.response.result) || {};
      const cols = (res.cols || []).map(c => c.name);
      const rows = (res.rows || []).map(row => {
        const o = {};
        row.forEach((c, j) => { o[cols[j]] = cellVal(c); });
        return o;
      });
      const affected = res.affected_row_count || 0;
      return {
        results: rows,
        success: true,
        meta: {
          rows_read: rows.length,
          rows_written: affected,
          changes: affected,
          duration: 0,
          last_row_id: res.last_insert_rowid != null ? Number(res.last_insert_rowid) : null,
        },
      };
    });
  }

  function prepare(sql) {
    return {
      bind(...args) { return { sql, args, run: () => runOne(sql, args), all: () => allOne(sql, args), first: () => firstOne(sql, args) }; },
      run: () => runOne(sql, []),
      all: () => allOne(sql, []),
      first: () => firstOne(sql, []),
    };
  }
  async function runOne(sql, args) { const r = await pipeline([{ sql, args }]); return r[0]; }
  async function allOne(sql, args) { const r = await pipeline([{ sql, args }]); return r[0]; }
  async function firstOne(sql, args) { const r = await pipeline([{ sql, args }]); return r[0].results.length ? r[0].results[0] : null; }

  return {
    prepare,
    async batch(stmts) {
      // D1 batch: array of bound statements ({sql,args} from prepare().bind()) -> array of results.
      const packed = stmts.map(s => ({ sql: s.sql, args: s.args || [] }));
      return pipeline(packed);
    },
  };
}
