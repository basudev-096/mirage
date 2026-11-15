import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

// Custom latency tracking trends
const directLatency = new Trend('direct_req_duration');
const proxyLatency = new Trend('proxy_req_duration');

export const options = {
  stages: [
    { duration: '5s', target: 20 },  // Ramp up to 20 VUs
    { duration: '10s', target: 50 }, // Sustained load at 50 VUs
    { duration: '5s', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'], // <1% errors
    proxy_req_duration: ['p(99)<50'], // Phase 1 acceptance target: <50ms p99 latency
  },
  insecureSkipTLSVerify: true, // Self-signed TLS dev certs
};

export default function () {
  const backendURL = __ENV.BACKEND_URL || 'http://127.0.0.1:8080';
  const proxyURL = __ENV.PROXY_URL || 'https://127.0.0.1:8443';

  // 1. Benchmark Direct Upstream Backend
  const directResp = http.get(`${backendURL}/search?q=test_query`);
  directLatency.add(directResp.timings.duration);
  check(directResp, {
    'direct status is 200': (r) => r.status === 200,
  });

  // 2. Benchmark Mirage Proxy Passthrough
  const proxyResp = http.get(`${proxyURL}/search?q=test_query`);
  proxyLatency.add(proxyResp.timings.duration);
  check(proxyResp, {
    'proxy status is 200': (r) => r.status === 200,
    'proxy backend header present': (r) => r.headers['X-Backend-Server'] === 'mirage-demo-backend',
  });

  sleep(0.01);
}
