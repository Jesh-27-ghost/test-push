const BASE = 'http://localhost:8000';

export const api = {
  chat: async (prompt, apiKey) => {
    const res = await fetch(`${BASE}/v1/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey || 'demo-key',
      },
      body: JSON.stringify({ prompt }),
    });
    return res.json();
  },

  simulate: async (prompt) => {
    const res = await fetch(`${BASE}/v1/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });
    return res.json();
  },

  stats: async () => {
    const res = await fetch(`${BASE}/v1/stats`);
    return res.json();
  },

  logs: async (limit = 50) => {
    const res = await fetch(`${BASE}/v1/logs?limit=${limit}`);
    return res.json();
  },

  clients: async () => {
    const res = await fetch(`${BASE}/v1/clients`);
    return res.json();
  },

  health: async () => {
    const res = await fetch(`${BASE}/v1/health`);
    return res.json();
  },
};
