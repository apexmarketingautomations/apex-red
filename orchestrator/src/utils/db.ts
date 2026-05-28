import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://apexred:apexred@localhost:5432/apexred',
});

export const db = {
  query: (text: string, params?: unknown[]) => pool.query(text, params),
};
