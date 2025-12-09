import Fastify from 'fastify';
import cors from '@fastify/cors';
import mysql from 'mysql2/promise';
import crypto from 'crypto';

const fastify = Fastify({ logger: true });

await fastify.register(cors, { origin: true });

const pool = mysql.createPool({
  host: '149.202.88.119',
  database: 'gs320506',
  user: 'gs320506',
  password: 'zNlb2143opFX',
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10
});

fastify.post('/api/login', async (request, reply) => {
  try {
    const { nickname, password } = request.body || {};

    if (!nickname || !password) {
      return reply.send({ success: false, error: 'Nickname and password required' });
    }

    const [rows] = await pool.execute(
      'SELECT NickName, Password FROM players WHERE NickName = ? LIMIT 1',
      [nickname.trim()]
    );

    if (rows.length === 0) {
      return reply.send({ success: false, error: 'Invalid credentials' });
    }

    if (rows[0].Password === password) {
      return reply.send({
        success: true,
        user: { nickname: rows[0].NickName, token: crypto.randomUUID() }
      });
    }

    return reply.send({ success: false, error: 'Invalid credentials' });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

fastify.get('/api/logs', async (request, reply) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, type, `desc`, DATE_FORMAT(`date`, '%Y-%m-%d') as date, TIME_FORMAT(time, '%H:%i:%s') as time FROM action_logs ORDER BY id DESC LIMIT 100"
    );
    return reply.send({ success: true, data: rows });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

fastify.get('/api/health', async () => ({ status: 'ok' }));

await fastify.listen({ port: process.env.PORT || 3001, host: '0.0.0.0' });
console.log('🚀 Server running');
