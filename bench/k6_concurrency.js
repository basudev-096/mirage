import http from 'k6/http';
import { check } from 'k6';

export const options = {
  summaryTrendStats: ['min', 'avg', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  scenarios: {
    concurrency_test: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.VUS || '100'),
      duration: '15s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
  insecureSkipTLSVerify: true,
};

export default function () {
  const url = __ENV.TARGET_URL || 'http://127.0.0.1:8080/search?q=bench';
  const res = http.get(url);
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  return {
    'stdout': JSON.stringify(data),
  };
}
