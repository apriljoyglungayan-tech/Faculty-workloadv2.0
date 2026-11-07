import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { DEFAULT_SCHEDULE } from './src/data/sampleData.js';
import { DEMO_ACCOUNTS } from './src/data/demoAccounts.js';
import type { AccountType, ClassScheduleItem, FacultyProfile } from './src/types/index.js';

export interface WorkloadDataset {
  id: string;
  period: string;
  facultyId: string;
  facultyName: string;
  college: string;
  department: string;
  teachingHours: number;
  adminHours: number;
  researchHours: number;
  extensionHours: number;
  reportCompletion: number;
}

export interface PortalUser {
  id: string;
  username: string;
  accountType: AccountType;
  profile: FacultyProfile;
  schedule: ClassScheduleItem[];
}

export interface PortalDocument {
  id: string;
  ownerId: string;
  ownerName: string;
  ownerUsername: string;
  ownerDepartment: string;
  kind: 'syllabus' | 'accomplishment' | 'lar' | 'error';
  title: string;
  payload: unknown;
  status: 'active' | 'archived' | 'error';
  createdAt: string;
  archivedAt: string | null;
}

export interface RegisteredFaculty {
  id: string;
  username: string;
  accountType: AccountType;
  profile: FacultyProfile;
  registeredAt: string;
  documentCount: number;
  archivedCount: number;
}

const databasePath = process.env.SQLITE_PATH || resolve(process.cwd(), 'data', 'faculty-workload.sqlite');
mkdirSync(dirname(databasePath), { recursive: true });

const database = new DatabaseSync(databasePath);

database.exec(`
  CREATE TABLE IF NOT EXISTS workload_datasets (
    id TEXT PRIMARY KEY,
    period TEXT NOT NULL,
    faculty_id TEXT NOT NULL,
    faculty_name TEXT NOT NULL,
    college TEXT NOT NULL,
    department TEXT NOT NULL,
    teaching_hours REAL NOT NULL,
    admin_hours REAL NOT NULL,
    research_hours REAL NOT NULL,
    extension_hours REAL NOT NULL,
    report_completion INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS portal_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    account_type TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    schedule_json TEXT NOT NULL,
    registered_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS portal_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES portal_users(id),
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS faculty_documents (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES portal_users(id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'archived', 'error')),
    created_at TEXT NOT NULL,
    archived_at TEXT
  );
`);

const rowCount = database.prepare('SELECT COUNT(*) AS count FROM workload_datasets').get() as { count: number };

if (rowCount.count === 0) {
  const departments = [
    'Computer Science & Information Technology',
    'Information Systems',
    'Mathematics',
    'Business Administration',
    'Tourism Management',
    'Legal Management',
  ];
  const periods = ['2026-07', '2026-08', '2026-09', '2026-10'];
  const insertDataset = database.prepare(`
    INSERT INTO workload_datasets (
      id, period, faculty_id, faculty_name, college, department,
      teaching_hours, admin_hours, research_hours, extension_hours, report_completion
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  database.exec('BEGIN');
  try {
    for (let facultyIndex = 0; facultyIndex < 18; facultyIndex += 1) {
      const facultyId = `DEMO-${String(facultyIndex + 1).padStart(3, '0')}`;
      const department = departments[facultyIndex % departments.length];

      for (let periodIndex = 0; periodIndex < periods.length; periodIndex += 1) {
        const period = periods[periodIndex];
        const id = `${facultyId}-${period}`;
        const teachingHours = 14 + ((facultyIndex * 7 + periodIndex * 3) % 16);
        const adminHours = 2 + ((facultyIndex + periodIndex * 2) % 6);
        const researchHours = 1 + ((facultyIndex * 3 + periodIndex) % 7);
        const extensionHours = 1 + ((facultyIndex + periodIndex * 3) % 5);
        const reportCompletion = 65 + ((facultyIndex * 11 + periodIndex * 9) % 36);

        insertDataset.run(
          id,
          period,
          facultyId,
          `Demo Faculty ${String(facultyIndex + 1).padStart(2, '0')}`,
          'Demo University College',
          department,
          teachingHours,
          adminHours,
          researchHours,
          extensionHours,
          reportCompletion,
        );
      }
    }
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function makePasswordHash(password: string, salt = randomBytes(16).toString('hex')) {
  return `${salt}:${scryptSync(password, salt, 32).toString('hex')}`;
}

function verifyPassword(password: string, storedHash: string) {
  const [salt, expectedHex] = storedHash.split(':');
  if (!salt || !expectedHex) return false;
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = scryptSync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function hashSessionToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

function mapPortalUser(row: {
  id: string;
  username: string;
  account_type: AccountType;
  profile_json: string;
  schedule_json: string;
}): PortalUser {
  return {
    id: row.id,
    username: row.username,
    accountType: row.account_type,
    profile: JSON.parse(row.profile_json) as FacultyProfile,
    schedule: JSON.parse(row.schedule_json) as ClassScheduleItem[],
  };
}

const findPortalUser = database.prepare(`
  SELECT id, username, account_type, profile_json, schedule_json
  FROM portal_users WHERE username = ?
`);

for (const account of DEMO_ACCOUNTS) {
  if (!findPortalUser.get(account.username)) {
    database.prepare(`
      INSERT INTO portal_users (id, username, password_hash, account_type, profile_json, schedule_json, registered_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(),
      account.username,
      makePasswordHash(account.password),
      account.accountType,
      JSON.stringify({ ...account.profile, accountType: account.accountType, email: account.username }),
      JSON.stringify(DEFAULT_SCHEDULE),
      new Date().toISOString(),
    );
  }
}

export function authenticatePortalUser(username: string, password: string): PortalUser | null {
  const row = database.prepare(`
    SELECT id, username, password_hash, account_type, profile_json, schedule_json
    FROM portal_users WHERE username = ?
  `).get(username.trim().toLowerCase()) as ({ password_hash: string } & Parameters<typeof mapPortalUser>[0]) | undefined;
  return row && verifyPassword(password, row.password_hash) ? mapPortalUser(row) : null;
}

export function registerPortalFaculty(username: string, password: string, profile: FacultyProfile): PortalUser {
  const normalizedUsername = username.trim().toLowerCase();
  const accountProfile = { ...profile, email: normalizedUsername, accountType: 'Faculty' as const };
  const id = randomUUID();
  database.prepare(`
    INSERT INTO portal_users (id, username, password_hash, account_type, profile_json, schedule_json, registered_at)
    VALUES (?, ?, ?, 'Faculty', ?, ?, ?)
  `).run(
    id,
    normalizedUsername,
    makePasswordHash(password),
    JSON.stringify(accountProfile),
    JSON.stringify(DEFAULT_SCHEDULE),
    new Date().toISOString(),
  );
  return getPortalUserById(id)!;
}

export function getPortalUserById(id: string): PortalUser | null {
  const row = database.prepare(`
    SELECT id, username, account_type, profile_json, schedule_json
    FROM portal_users WHERE id = ?
  `).get(id) as Parameters<typeof mapPortalUser>[0] | undefined;
  return row ? mapPortalUser(row) : null;
}

export function createPortalSession(userId: string) {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  database.prepare('DELETE FROM portal_sessions WHERE expires_at <= ?').run(Date.now());
  database.prepare('INSERT INTO portal_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hashSessionToken(token), userId, expiresAt);
  return token;
}

export function getPortalUserForSession(token: string): PortalUser | null {
  const row = database.prepare(`
    SELECT u.id, u.username, u.account_type, u.profile_json, u.schedule_json
    FROM portal_sessions s JOIN portal_users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(hashSessionToken(token), Date.now()) as Parameters<typeof mapPortalUser>[0] | undefined;
  return row ? mapPortalUser(row) : null;
}

export function revokePortalSession(token: string) {
  database.prepare('DELETE FROM portal_sessions WHERE token_hash = ?').run(hashSessionToken(token));
}

export function updatePortalWorkspace(userId: string, profile: FacultyProfile, schedule: ClassScheduleItem[]) {
  const user = getPortalUserById(userId);
  if (!user) return false;
  const savedProfile: FacultyProfile = {
    ...profile,
    email: user.username,
    accountType: user.accountType,
  };
  database.prepare('UPDATE portal_users SET profile_json = ?, schedule_json = ? WHERE id = ?')
    .run(JSON.stringify(savedProfile), JSON.stringify(schedule), userId);
  return true;
}

export function createFacultyDocument(
  ownerId: string,
  kind: 'syllabus' | 'accomplishment' | 'lar',
  title: string,
  payload: unknown,
) {
  const id = randomUUID();
  database.prepare(`
    INSERT INTO faculty_documents (id, owner_id, kind, title, payload_json, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'active', ?)
  `).run(id, ownerId, kind, title, JSON.stringify(payload), new Date().toISOString());
  return id;
}

export function createDocumentError(ownerId: string, title: string, message: string) {
  const id = randomUUID();
  database.prepare(`
    INSERT INTO faculty_documents (id, owner_id, kind, title, payload_json, status, created_at)
    VALUES (?, ?, 'error', ?, ?, 'error', ?)
  `).run(id, ownerId, title, JSON.stringify({ message }), new Date().toISOString());
  return id;
}

export function updateFacultyDocument(documentId: string, ownerId: string, title: string, payload: unknown) {
  const document = database.prepare('SELECT owner_id, status FROM faculty_documents WHERE id = ?')
    .get(documentId) as { owner_id: string; status: PortalDocument['status'] } | undefined;
  if (!document || document.owner_id !== ownerId || document.status !== 'active') return false;
  database.prepare('UPDATE faculty_documents SET title = ?, payload_json = ? WHERE id = ?')
    .run(title, JSON.stringify(payload), documentId);
  return true;
}

export function listFacultyDocuments(ownerId?: string): PortalDocument[] {
  const query = `
    SELECT d.id, d.owner_id AS ownerId, d.kind, d.title, d.payload_json AS payloadJson,
      d.status, d.created_at AS createdAt, d.archived_at AS archivedAt,
      u.username AS ownerUsername, u.profile_json AS profileJson
    FROM faculty_documents d JOIN portal_users u ON u.id = d.owner_id
    ${ownerId ? 'WHERE d.owner_id = ?' : ''}
    ORDER BY d.created_at DESC
  `;
  const rows = (ownerId
    ? database.prepare(query).all(ownerId)
    : database.prepare(query).all()) as unknown as Array<{
      id: string;
      ownerId: string;
      kind: PortalDocument['kind'];
      title: string;
      payloadJson: string;
      status: PortalDocument['status'];
      createdAt: string;
      archivedAt: string | null;
      ownerUsername: string;
      profileJson: string;
    }>;

  return rows.map((row) => {
    const profile = JSON.parse(row.profileJson) as FacultyProfile;
    return {
      id: row.id,
      ownerId: row.ownerId,
      ownerName: profile.name,
      ownerUsername: row.ownerUsername,
      ownerDepartment: profile.department,
      kind: row.kind,
      title: row.title,
      payload: JSON.parse(row.payloadJson),
      status: row.status,
      createdAt: row.createdAt,
      archivedAt: row.archivedAt,
    };
  });
}

export function archiveFacultyDocument(documentId: string, ownerId: string) {
  const document = database.prepare('SELECT owner_id, status FROM faculty_documents WHERE id = ?')
    .get(documentId) as { owner_id: string; status: PortalDocument['status'] } | undefined;
  if (!document || document.owner_id !== ownerId || document.status === 'archived') return false;
  database.prepare(`UPDATE faculty_documents SET status = 'archived', archived_at = ? WHERE id = ?`)
    .run(new Date().toISOString(), documentId);
  return true;
}

export function listRegisteredFaculty(): RegisteredFaculty[] {
  const rows = database.prepare(`
    SELECT u.id, u.username, u.account_type AS accountType, u.profile_json AS profileJson,
      u.registered_at AS registeredAt,
      COUNT(d.id) AS documentCount,
      SUM(CASE WHEN d.status IN ('archived', 'error') THEN 1 ELSE 0 END) AS archivedCount
    FROM portal_users u LEFT JOIN faculty_documents d ON d.owner_id = u.id
    WHERE u.account_type != 'Administrator'
    GROUP BY u.id
    ORDER BY u.registered_at DESC
  `).all() as unknown as Array<{
    id: string;
    username: string;
    accountType: AccountType;
    profileJson: string;
    registeredAt: string;
    documentCount: number;
    archivedCount: number | null;
  }>;

  return rows.map((row) => ({
    id: row.id,
    username: row.username,
    accountType: row.accountType,
    profile: JSON.parse(row.profileJson) as FacultyProfile,
    registeredAt: row.registeredAt,
    documentCount: row.documentCount,
    archivedCount: row.archivedCount || 0,
  }));
}

export function getDashboardDataset(): { datasetCount: number; records: WorkloadDataset[] } {
  const records = database.prepare(`
    SELECT
      id,
      period,
      faculty_id AS facultyId,
      faculty_name AS facultyName,
      college,
      department,
      teaching_hours AS teachingHours,
      admin_hours AS adminHours,
      research_hours AS researchHours,
      extension_hours AS extensionHours,
      report_completion AS reportCompletion
    FROM workload_datasets
    ORDER BY period, faculty_id
  `).all() as unknown as WorkloadDataset[];

  return { datasetCount: records.length, records };
}