const KV_BINDING_NAME = 'EMBY_CONFIG_KV';
const CONFIG_KEY = 'emby_config';

const FALLBACK_CONFIG = {
  paths: {
    "/tv1": "https://emby1.example.com:8920",
    "/tv2": "https://emby2.example.com:8920"
  },
  main: "https://default-emby.example.com:8920",
  cors: true
};

export default {
  async fetch(req, env, ctx) {
    const rawUrl = new URL(req.url);

    let config = FALLBACK_CONFIG;
    try {
      const stored = await env[KV_BINDING_NAME].get(CONFIG_KEY, { type: 'json' });
      if (stored && (stored.paths || stored.main)) {
        config = stored;
      }
    } catch (e) {}

    let target = config.main || FALLBACK_CONFIG.main;
    let prefix = "";

    for (const key in config.paths) {
      if (rawUrl.pathname.startsWith(key)) {
        target = config.paths[key];
        prefix = key;
        break;
      }
    }

    let cleanPath = rawUrl.pathname;
    if (prefix) {
      cleanPath = cleanPath.slice(prefix.length);
      if (!cleanPath || cleanPath[0] !== '/') cleanPath = '/' + cleanPath;
    }

    const tUrl = new URL(target);
    const finalUrl = new URL(cleanPath + rawUrl.search, tUrl);

    const h = new Headers(req.headers);
    h.set('Host', tUrl.host);
    if (h.has('Referer')) h.set('Referer', target);
    if (h.has('Origin')) h.set('Origin', target);

    const newReq = new Request(finalUrl.toString(), {
      method: req.method,
      headers: h,
      body: req.body,
      redirect: 'follow'
    });

    try {
      const res = await fetch(newReq);
      const resH = new Headers(res.headers);

      if (config.cors !== false) {
        resH.set('Access-Control-Allow-Origin', '*');
        resH.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        resH.set('Access-Control-Allow-Headers', '*');
      }

      return new Response(res.body, {
        status: res.status,
        statusText: res.statusText,
        headers: resH
      });
    } catch (err) {
      return new Response('Proxy error: ' + err.message, { status: 502 });
    }
  }
};