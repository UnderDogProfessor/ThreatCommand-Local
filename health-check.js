const http = require('http');
const request = http.get('http://127.0.0.1:3000', (response) => {
  if (response.statusCode === 200) { console.log('Healthy: ThreatCommand Local responded on localhost:3000'); process.exit(0); }
  console.error(`Unhealthy: HTTP ${response.statusCode}`); process.exit(1);
});
request.setTimeout(3000, () => { request.destroy(); console.error('Unhealthy: no local response'); process.exit(1); });
request.on('error', () => { console.error('Unhealthy: start the local server first'); process.exit(1); });
