import pg from 'pg';

const DB = process.env.DATABASE_URL ?? 'postgresql://apexmarketingautomations@localhost:5432/apexred';
export const pool = new pg.Pool({ connectionString: DB });
