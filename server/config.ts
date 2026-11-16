import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';

dotenv.config();

const port = parseInt(process.env.PORT || '3000', 10);
const trafficLogPath = process.env.TRAFFIC_LOG_PATH || path.resolve(process.cwd(), 'traffic.jsonl');
const featuresLogPath = process.env.FEATURES_LOG_PATH || path.resolve(process.cwd(), 'features.jsonl');
const maxInMemoryRecords = parseInt(process.env.MAX_IN_MEMORY_RECORDS || '5000', 10);
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || 'admin123';
const alertWebhookUrl = process.env.ALERT_WEBHOOK_URL || '';
const hashIps = process.env.HASH_IPS === 'true';
const ipHashSalt = process.env.IP_HASH_SALT || crypto.randomBytes(16).toString('hex');
const appUrl = process.env.APP_URL && process.env.APP_URL !== 'MY_APP_URL'
  ? process.env.APP_URL.replace(/\/$/, '')
  : `http://localhost:${port}`;

export function isWeakAdminPassword(pass: string = adminPass): boolean {
  return !pass || pass === 'admin123' || pass.length < 8;
}

export function hashClientIp(
  ip: string,
  shouldHash: boolean = hashIps,
  salt: string = ipHashSalt
): string {
  const cleanIp = (ip || 'unknown').trim();
  if (!shouldHash) return cleanIp;
  return 'ip_' + crypto.createHmac('sha256', salt).update(cleanIp).digest('hex').slice(0, 16);
}

export const config = {
  port,
  trafficLogPath,
  featuresLogPath,
  maxInMemoryRecords,
  adminUser,
  adminPass,
  alertWebhookUrl,
  hashIps,
  ipHashSalt,
  appUrl,
};
