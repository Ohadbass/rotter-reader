const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = 3001;
const ROTTER_URL = 'https://rotter.net/scoopscache.html';
const HTML_FILE = path.join(__dirname, 'rotter.html');

function fetchRotterScoops() {
  return new Promise((resolve, reject) => {
    https
      .get(
        ROTTER_URL,
        {
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; rotter-reader/1.0)',
          },
        },
        (res) => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`HTTP ${res.statusCode}`));
            res.resume();
            return;
          }

          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => resolve(Buffer.concat(chunks)));
          res.on('error', reject);
        }
      )
      .on('error', reject);
  });
}

function serveRotterHtml(res) {
  fs.readFile(HTML_FILE, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Failed to load rotter.html');
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const pathname = req.url.split('?')[0];

  if (req.method === 'GET' && pathname === '/scoops') {
    try {
      const buffer = await fetchRotterScoops();
      const html = new TextDecoder('windows-1255').decode(buffer);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(html);
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(err.message);
    }
    return;
  }

  if (req.method === 'GET') {
    serveRotterHtml(res);
    return;
  }

  res.writeHead(405, { 'Content-Type': 'text/plain' });
  res.end('Method Not Allowed');
});

server.listen(PORT, () => {
  console.log(`Rotter reader server running at http://localhost:${PORT}`);
});
