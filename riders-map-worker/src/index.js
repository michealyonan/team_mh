import { DurableObject } from 'cloudflare:workers';

const MAX_BODY_BYTES = 2_000_000;
const SNAPSHOT_TTL_MS = 15 * 60 * 1000;

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowedOrigin = env.ALLOWED_ORIGIN || '*';
    if (origin && allowedOrigin !== '*' && origin !== allowedOrigin) return new Response('Origin not allowed', { status: 403 });
    const corsOrigin = allowedOrigin === '*' ? '*' : allowedOrigin;
    const cors = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    const url = new URL(request.url);
    const hub = env.RIDER_MAP_HUB.get(env.RIDER_MAP_HUB.idFromName('riders-global'));

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (url.pathname === '/health' && request.method === 'GET') return json({ ok: true });

    if (url.pathname === '/api/publish' && request.method === 'POST') {
      if (!env.APP_INGEST_TOKEN || !safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.APP_INGEST_TOKEN}`)) return json({ error: 'unauthorized' }, 401);
      let payload;
      try {
        if (Number(request.headers.get('Content-Length') || 0) > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413);
        const raw = await request.text();
        if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413);
        payload = JSON.parse(raw);
      } catch {
        return json({ error: 'invalid_json' }, 400);
      }
      if (!payload || !Array.isArray(payload.riders) || payload.riders.length > 5000) return json({ error: 'invalid_riders' }, 400);
      const riders = payload.riders.map((row) => {
        const latitude = Number(row?.latitude), longitude = Number(row?.longitude);
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || Math.abs(latitude) > 90 || Math.abs(longitude) > 180 || (latitude === 0 && longitude === 0)) return null;
        const activeOrders = Array.isArray(row.active_orders) ? row.active_orders.slice(0, 20).map((order) => ({
          id: clean(order?.id, 60), status: clean(order?.status, 40),
          restaurant: clean(order?.restaurant, 100), waiting_since: clean(order?.waiting_since, 40),
          wait_minutes: finiteNumber(order?.wait_minutes, 0, 100000),
        })) : [];
        const activeDeliveryIds = Array.isArray(row.active_delivery_ids)
          ? row.active_delivery_ids.slice(0, 20).map((id) => clean(id, 60)) : [];
        return {
          id: clean(row.id, 60), name: clean(row.name, 120), city: clean(row.city, 80),
          zone: clean(row.zone, 100), state: clean(row.state, 40), latitude, longitude,
          updated_at: clean(row.updated_at, 40),
          deliveries: clean(row.deliveries, 30), time_worked: clean(row.time_worked, 40),
          late_time: clean(row.late_time, 40), breaks: clean(row.breaks, 20),
          breaks_time: clean(row.breaks_time, 40), acceptance_rate: clean(row.acceptance_rate, 30),
          utilization_rate: clean(row.utilization_rate, 30), wallet_balance: clean(row.wallet_balance, 30),
          ongoing_orders: finiteNumber(row.ongoing_orders, 0, 100000) ?? Math.max(activeOrders.length, activeDeliveryIds.length),
          active_delivery_ids: activeDeliveryIds, active_orders: activeOrders,
        };
      }).filter(Boolean);
      const snapshot = { updated_at: clean(payload.updated_at, 40) || new Date().toISOString(), riders };
      const stored = await hub.fetch('https://rider-map.internal/publish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(snapshot),
      });
      if (!stored.ok) return json({ error: 'could_not_store_snapshot' }, 503);
      return json({ ok: true, riders: riders.length, updated_at: snapshot.updated_at });
    }

    if (url.pathname === '/api/riders' && request.method === 'GET') {
      if (!env.MAP_VIEW_TOKEN || !safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.MAP_VIEW_TOKEN}`)) return json({ error: 'unauthorized' }, 401);
      const response = await hub.fetch('https://rider-map.internal/snapshot');
      return json(await response.json());
    }

    if (url.pathname === '/api/ws-ticket' && request.method === 'POST') {
      if (!env.MAP_VIEW_TOKEN || !safeEqual(request.headers.get('Authorization') || '', `Bearer ${env.MAP_VIEW_TOKEN}`)) return json({ error: 'unauthorized' }, 401);
      const ticket = `${crypto.randomUUID()}${crypto.randomUUID()}`;
      const response = await hub.fetch('https://rider-map.internal/ticket', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket }),
      });
      if (!response.ok) return json({ error: 'could_not_create_ticket' }, 503);
      return json({ ticket });
    }

    if (url.pathname === '/ws' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      if (!url.searchParams.get('ticket')) return new Response('Missing ticket', { status: 401 });
      const doRequest = new Request(`https://rider-map.internal/ws?ticket=${encodeURIComponent(url.searchParams.get('ticket'))}`, request);
      return hub.fetch(doRequest);
    }

    return json({ error: 'not_found' }, 404);
  },
};

export class RiderMapHub extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/publish' && request.method === 'POST') {
      const snapshot = await request.json();
      await this.ctx.storage.put('snapshot', snapshot);
      await this.ctx.storage.setAlarm(Date.now() + SNAPSHOT_TTL_MS);
      const message = JSON.stringify({ type: 'snapshot', snapshot });
      for (const socket of this.ctx.getWebSockets()) {
        try { socket.send(message); } catch { try { socket.close(1011, 'send failed'); } catch {} }
      }
      return Response.json({ ok: true });
    }
    if (url.pathname === '/snapshot' && request.method === 'GET') {
      const snapshot = await this.ctx.storage.get('snapshot');
      if (!snapshot || Date.now() - Date.parse(snapshot.updated_at) > SNAPSHOT_TTL_MS) return Response.json({ updated_at: null, riders: [] });
      return Response.json(snapshot);
    }
    if (url.pathname === '/ticket' && request.method === 'POST') {
      const { ticket } = await request.json();
      await this.ctx.storage.put(`ticket:${ticket}`, Date.now() + 30_000);
      return Response.json({ ok: true });
    }
    if (url.pathname === '/ws' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const ticket = url.searchParams.get('ticket') || '';
      const expires = await this.ctx.storage.get(`ticket:${ticket}`);
      await this.ctx.storage.delete(`ticket:${ticket}`);
      if (!expires || expires < Date.now()) return new Response('Invalid or expired ticket', { status: 401 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ connectedAt: Date.now() });
      const snapshot = await this.ctx.storage.get('snapshot');
      if (snapshot && Date.now() - Date.parse(snapshot.updated_at) <= SNAPSHOT_TTL_MS) {
        server.send(JSON.stringify({ type: 'snapshot', snapshot }));
      }
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response('Not found', { status: 404 });
  }

  async alarm() {
    const snapshot = await this.ctx.storage.get('snapshot');
    if (snapshot && Date.now() - Date.parse(snapshot.updated_at) >= SNAPSHOT_TTL_MS) await this.ctx.storage.delete('snapshot');
    for (const key of await this.ctx.storage.list({ prefix: 'ticket:' })) {
      if (key[1] < Date.now()) await this.ctx.storage.delete(key[0]);
    }
  }

  async webSocketMessage(socket, message) {
    if (message === 'ping') socket.send('pong');
  }
}

function clean(value, maxLength) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLength);
}

function finiteNumber(value, min, max) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let index = 0; index < a.length; index++) mismatch |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return mismatch === 0;
}
