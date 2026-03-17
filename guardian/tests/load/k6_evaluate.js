/**
 * Guardian Load Test — k6 script for /v1/evaluate
 *
 * Measures throughput and latency under load.
 *
 * Install k6: https://k6.io/docs/get-started/installation/
 *
 * Run locally:
 *   k6 run --vus 10 --duration 30s tests/load/k6_evaluate.js
 *
 * Run against Render:
 *   K6_GUARDIAN_URL=https://guardian-np0a.onrender.com k6 run tests/load/k6_evaluate.js
 *
 * Stages (ramp-up pattern):
 *   0-10s:  ramp to 5 VUs
 *   10-40s: hold 5 VUs (warm-up)
 *   40-70s: ramp to 20 VUs (sustained load)
 *   70-80s: ramp to 50 VUs (peak)
 *   80-90s: ramp down to 0
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.K6_GUARDIAN_URL || 'http://localhost:8000';
const API_KEY = __ENV.K6_GUARDIAN_API_KEY || '';

// Custom metrics
const evaluationDuration = new Trend('guardian_evaluation_duration', true);
const blockRate = new Rate('guardian_block_rate');
const errorRate = new Rate('guardian_error_rate');

export const options = {
  stages: [
    { duration: '10s', target: 5 },
    { duration: '30s', target: 5 },
    { duration: '30s', target: 20 },
    { duration: '10s', target: 50 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],     // 95th percentile < 2s
    guardian_error_rate: ['rate<0.05'],     // Error rate < 5%
    http_req_failed: ['rate<0.05'],
  },
};

// Diverse test payloads to exercise different pipeline paths
const PAYLOADS = [
  {
    actor_name: 'deploy-bot-prod',
    actor_type: 'automation',
    requested_action: 'change_configuration',
    target_system: 'aws-ec2',
    target_asset: 'prod/ec2/web-fleet',
    privilege_level: 'standard',
    sensitivity_level: 'internal',
    business_context: 'Routine deployment',
  },
  {
    actor_name: 'terraform-cloud-runner',
    actor_type: 'automation',
    requested_action: 'destroy_infrastructure',
    target_system: 'aws-vpc-prod',
    target_asset: 'vpc-prod-main',
    privilege_level: 'admin',
    sensitivity_level: 'restricted',
    business_context: 'Terraform destroy plan',
  },
  {
    actor_name: 'infra-agent-prod',
    actor_type: 'ai_agent',
    requested_action: 'disable_endpoint_protection',
    target_system: 'server-fleet-prod',
    target_asset: 'endpoint-protection-group-A',
    privilege_level: 'elevated',
    sensitivity_level: 'high',
    business_context: 'AI agent remediation action',
  },
  {
    actor_name: 'alice.chen',
    actor_type: 'human',
    requested_action: 'modify_firewall_rule',
    target_system: 'aws-vpc-prod',
    target_asset: 'sg-0a1b2c3d',
    privilege_level: 'elevated',
    sensitivity_level: 'high',
    business_context: 'Security group update for new service',
  },
  {
    actor_name: 'unknown-actor-' + Math.random().toString(36).substr(2, 8),
    actor_type: 'human',
    requested_action: 'grant_admin_access',
    target_system: 'aws-iam',
    target_asset: 'role-admin',
    privilege_level: 'admin',
    sensitivity_level: 'restricted',
    business_context: 'Unknown actor test',
  },
];

export default function () {
  const payload = PAYLOADS[Math.floor(Math.random() * PAYLOADS.length)];
  // Add timestamp
  payload.timestamp = new Date().toISOString();

  const headers = { 'Content-Type': 'application/json' };
  if (API_KEY) {
    headers['Authorization'] = `Bearer ${API_KEY}`;
  }

  const res = http.post(`${BASE_URL}/v1/evaluate`, JSON.stringify(payload), {
    headers,
    timeout: '10s',
  });

  // Record metrics
  evaluationDuration.add(res.timings.duration);
  errorRate.add(res.status >= 400 && res.status !== 403); // 403 = blocked, not an error

  const body = res.json();
  if (body) {
    blockRate.add(body.decision === 'block');
  }

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has decision': (r) => r.json('decision') !== undefined,
    'has risk_score': (r) => r.json('risk_score') !== undefined,
    'response time < 2s': (r) => r.timings.duration < 2000,
  });

  sleep(0.1); // Small pause between requests per VU
}

export function handleSummary(data) {
  const p50 = data.metrics.http_req_duration.values['p(50)'];
  const p95 = data.metrics.http_req_duration.values['p(95)'];
  const p99 = data.metrics.http_req_duration.values['p(99)'];
  const rps = data.metrics.http_reqs.values.rate;
  const total = data.metrics.http_reqs.values.count;
  const errors = data.metrics.http_req_failed.values.rate;

  console.log('\n=== Guardian Load Test Results ===');
  console.log(`Total requests:    ${total}`);
  console.log(`Requests/sec:      ${rps.toFixed(1)}`);
  console.log(`p50 latency:       ${p50.toFixed(0)}ms`);
  console.log(`p95 latency:       ${p95.toFixed(0)}ms`);
  console.log(`p99 latency:       ${p99.toFixed(0)}ms`);
  console.log(`Error rate:        ${(errors * 100).toFixed(1)}%`);
  console.log('=================================\n');

  return {};
}
