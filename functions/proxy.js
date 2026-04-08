const https = require('https');
const http = require('http');

exports.handler = async function(event, context) {
  const TOKEN = 'VjFYQWlwZDVCZ2ZIMm9TV3BFcndIeGxZbkdBelNESGNDVzh2czBWaHF1Yz0';
  const BASE_HOST = 'api.marketdata.app';

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const params = { ...(event.queryStringParameters || {}) };
  const mdPath = params.path || 'stocks/quotes/AAPL/';
  delete params.path;
  params.token = TOKEN;

  const queryStr = Object.entries(params).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const fullPath = `/v1/${mdPath}?${queryStr}`;

  console.log('Proxying to:', `https://${BASE_HOST}${fullPath}`);

  return new Promise((resolve) => {
    const options = {
      hostname: BASE_HOST,
      path: fullPath,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'MarketWatchPro/1.0'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log('Response status:', res.statusCode);
        console.log('Response body:', data.slice(0, 200));
        resolve({
          statusCode: res.statusCode,
          headers: corsHeaders,
          body: data
        });
      });
    });

    req.on('error', (err) => {
      console.error('Request error:', err.message);
      resolve({
        statusCode: 500,
        headers: corsHeaders,
        body: JSON.stringify({ s: 'error', errmsg: err.message })
      });
    });

    req.setTimeout(25000, () => {
      req.destroy();
      resolve({
        statusCode: 504,
        headers: corsHeaders,
        body: JSON.stringify({ s: 'error', errmsg: 'Request timeout' })
      });
    });

    req.end();
  });
};
