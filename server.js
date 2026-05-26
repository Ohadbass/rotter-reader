const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = 3001;
const ROTTER_URL = 'https://rotter.net/scoopscache.html';
const HTML_FILE = path.join(__dirname, 'rotter.html');
const CONFIG_PATH = path.join(__dirname, 'config.json');

let CONFIG = {};
try {
  CONFIG = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} catch (err) {
  console.warn('Warning: config.json not found — Google TTS will not work');
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function synthesizeSpeech(text) {
  return new Promise((resolve, reject) => {
    const apiKey = CONFIG.googleTtsApiKey;
    if (!apiKey) {
      reject(new Error('Google TTS API key not configured'));
      return;
    }

    const url = `https://texttospeech.googleapis.com/v1/text:synthesize?key=${apiKey}`;
    const body = JSON.stringify({
      input: { text },
      voice: { languageCode: 'he-IL', name: 'he-IL-Wavenet-D' },
      audioConfig: { audioEncoding: 'MP3', speakingRate: 1.0 },
    });

    const request = https.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const responseBody = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 400) {
            reject(new Error(responseBody || `HTTP ${res.statusCode}`));
            return;
          }

          try {
            const parsed = JSON.parse(responseBody);
            resolve(Buffer.from(parsed.audioContent, 'base64'));
          } catch (err) {
            reject(err);
          }
        });
        res.on('error', reject);
      }
    );

    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

function fetchUrl(rawUrl, maxRedirects = 5) {
  if (maxRedirects <= 0) {
    return Promise.reject(new Error('Too many redirects'));
  }

  return new Promise((resolve, reject) => {
    const client = rawUrl.startsWith('https:') ? https : http;

    client
      .get(
        rawUrl,
        {
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; rotter-reader/1.0)',
          },
        },
        (res) => {
          const redirectCodes = [301, 302, 303, 307, 308];
          if (redirectCodes.includes(res.statusCode) && res.headers.location) {
            let location = res.headers.location;
            if (location.startsWith('/')) {
              location = 'https://rotter.net' + location;
            }
            res.resume();
            fetchUrl(location, maxRedirects - 1).then(resolve).catch(reject);
            return;
          }

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

function fetchRotterScoops() {
  return fetchUrl(ROTTER_URL);
}

function isAllowedRotterUrl(url) {
  return url.startsWith('https://rotter.net') || url.startsWith('http://rotter.net');
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

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  if (req.method === 'POST' && pathname === '/tts') {
    try {
      const rawBody = await readRequestBody(req);
      const payload = JSON.parse(rawBody);
      let text = payload.text;

      if (!text) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing text field');
        return;
      }

      if (text.length > 4500) {
        text = text.slice(0, 4500);
      }

      const audioBuffer = await synthesizeSpeech(text);
      res.writeHead(200, {
        'Content-Type': 'audio/mpeg',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(audioBuffer);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(err.message);
    }
    return;
  }

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

  if (req.method === 'GET' && pathname === '/article') {
    const requestUrl = new URL(req.url, `http://localhost:${PORT}`);
    const articleUrl = requestUrl.searchParams.get('url');

    if (!articleUrl || !isAllowedRotterUrl(articleUrl)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    try {
      const buffer = await fetchUrl(articleUrl);
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
