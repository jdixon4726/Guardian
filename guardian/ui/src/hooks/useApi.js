import { useState, useEffect, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

export function useApi(endpoint, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { autoRefresh = 0, enabled = true } = options;

  const fetchData = useCallback(async () => {
    if (!enabled) return;
    try {
      setLoading(true);
      const headers = {};
      const apiKey = import.meta.env.VITE_API_KEY;
      if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

      const res = await fetch(`${API_BASE}${endpoint}`, { headers });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const json = await res.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [endpoint, enabled]);

  useEffect(() => {
    fetchData();
    if (autoRefresh > 0) {
      const interval = setInterval(fetchData, autoRefresh);
      return () => clearInterval(interval);
    }
  }, [fetchData, autoRefresh]);

  return { data, loading, error, refetch: fetchData };
}

export async function postApi(endpoint, body) {
  const headers = { 'Content-Type': 'application/json' };
  const apiKey = import.meta.env.VITE_API_KEY;
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}
