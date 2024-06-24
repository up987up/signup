// config/db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false // Note: Set to true for production with a valid certificate
  }
});
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err); // Log errors
  process.exit(-1);
});

module.exports = pool;
