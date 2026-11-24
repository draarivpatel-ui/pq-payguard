// serve.mjs - zero-dependency static dev server for PQ PayGuard.
// `npm run dev` (default 5173) or `--port N` / `--port 0` for ephemeral.

import http from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.md': 'text/markdown; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

const portIdx = process.argv.indexOf('--port');
const port = portIdx >= 0 ? Number(process.argv[portIdx + 1]) : Number(process.env.PORT || 5173);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/index.html';
  const filePath = normalize(join(root, pathname));
  if (!filePath.startsWith(root)) {
    res.writeHead(403).end('forbidden');
    return;
  }
  let st;
  try {
    st = statSync(filePath);
  } catch {
    res.writeHead(404).end('not found');
    return;
  }
  if (st.isDirectory()) {
    res.writeHead(404).end('not found');
    return;
  }
  res.writeHead(200, {
    'Content-Type': MIME[extname(filePath)] || 'application/octet-stream',
    'Content-Length': st.size,
    'Cache-Control': 'no-store',
  });
  createReadStream(filePath).pipe(res);
});

server.listen(port, '127.0.0.1', () => {
  const actual = server.address().port;
  console.log(`PQ PayGuard dev server: http://localhost:${actual}/`);
  console.log(`PORT=${actual}`);
});
