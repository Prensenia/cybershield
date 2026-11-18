// Vercel serverless entry for the CyberShield API.
// vercel.json rewrites send every /api/* request here, carrying the original
// sub-path in the __api query parameter so the Express routes always match,
// regardless of how Vercel presents req.url to the function.
import app from '../server/index.js';

export default function handler(req, res) {
  let url = req.url || '/';
  const queryIndex = url.indexOf('?');

  // Case A: Vercel hands us the rewritten function path instead of the original request.
  if (url.startsWith('/api/index.js')) {
    const search = queryIndex >= 0 ? url.slice(queryIndex + 1) : '';
    const params = new URLSearchParams(search);
    const originalPath = params.get('__api');
    if (originalPath != null) {
      params.delete('__api');
      const rest = params.toString();
      url = `/api/${originalPath}${rest ? `?${rest}` : ''}`;
    } else {
      url = '/api';
    }
  } else if (queryIndex >= 0) {
    // Case B: the original path arrived intact — just make sure the /api prefix is present.
    const search = url.slice(queryIndex + 1);
    if (search.startsWith('__api=')) {
      const params = new URLSearchParams(search);
      const originalPath = params.get('__api');
      params.delete('__api');
      const rest = params.toString();
      url = `/api/${originalPath || ''}${rest ? `?${rest}` : ''}`;
    }
  }

  if (!url.startsWith('/api')) url = url === '/' ? '/api' : `/api${url}`;
  req.url = url;

  if (url.split('?')[0] === '/api/__diag') {
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) if (key.startsWith('x-')) headers[key] = Array.isArray(value) ? value.join(',') : value;
    return res.status(200).json({ __diag: true, resolvedUrl: url, method: req.method, headers });
  }

  return app(req, res);
}
