import Fastify from 'fastify';
import cors from '@fastify/cors';
import mysql from 'mysql2/promise';
import crypto from 'crypto';

const fastify = Fastify({ logger: true });

// CORS
await fastify.register(cors, { origin: true });

// Хранилище активных токенов (в production использовать Redis)
const activeSessions = new Map();

// Время жизни сессии - 10 минут
const SESSION_DURATION = 10 * 60 * 1000;

// MySQL pool
const pool = mysql.createPool({
  host: '149.202.88.119',
  database: 'gs320506',
  user: 'gs320506',
  password: 'zNlb2143opFX',
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10
});

// Middleware для проверки авторизации
const authMiddleware = async (request, reply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.status(401).send({ success: false, error: 'Unauthorized' });
  }

  const token = authHeader.substring(7);
  const session = activeSessions.get(token);

  if (!session) {
    return reply.status(401).send({ success: false, error: 'Invalid token' });
  }

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return reply.status(401).send({ success: false, error: 'Session expired' });
  }

  // Продлеваем сессию при активности
  session.expiresAt = Date.now() + SESSION_DURATION;
  request.user = session.user;
};

// Очистка устаревших сессий каждые 5 минут
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(token);
    }
  }
}, 5 * 60 * 1000);

// POST /api/login - Шаг 1: проверка логина/пароля
fastify.post('/api/login', async (request, reply) => {
  try {
    const { nickname, password } = request.body || {};

    if (!nickname || !password) {
      return reply.send({ success: false, error: 'Nickname and password required' });
    }

    // Защита от инъекций через длину
    if (typeof nickname !== 'string' || typeof password !== 'string') {
      return reply.send({ success: false, error: 'Invalid input type' });
    }

    if (nickname.length > 50 || password.length > 255) {
      return reply.send({ success: false, error: 'Invalid input length' });
    }

    const [rows] = await pool.execute(
      'SELECT NickName, Password, Admin FROM players WHERE NickName = ? LIMIT 1',
      [nickname.trim()]
    );

    if (rows.length === 0) {
      return reply.send({ success: false, error: 'Invalid credentials' });
    }

    const player = rows[0];

    if (player.Password !== password) {
      return reply.send({ success: false, error: 'Invalid credentials' });
    }

    // Проверка уровня админа
    if (player.Admin <= 7) {
      return reply.send({ success: false, error: 'Недостаточно прав для входа' });
    }

    // Генерируем временный токен для 2FA
    const tempToken = crypto.randomUUID();
    const confirmCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-значный код

    // Сохраняем pending сессию (5 минут на ввод кода)
    activeSessions.set(tempToken, {
      user: { nickname: player.NickName, admin: player.Admin },
      confirmCode,
      isPending: true,
      expiresAt: Date.now() + 5 * 60 * 1000
    });

    // В реальном приложении здесь отправка кода в Telegram
    // Для тестирования выводим в логи (убрать в production!)
    fastify.log.info(`2FA Code for ${player.NickName}: ${confirmCode}`);

    return reply.send({
      success: true,
      requireConfirmation: true,
      tempToken,
      // Для тестирования - убрать в production!
      _testCode: confirmCode
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// POST /api/confirm - Шаг 2: проверка кода подтверждения
fastify.post('/api/confirm', async (request, reply) => {
  try {
    const { tempToken, code } = request.body || {};

    if (!tempToken || !code) {
      return reply.send({ success: false, error: 'Token and code required' });
    }

    const session = activeSessions.get(tempToken);

    if (!session || !session.isPending) {
      return reply.send({ success: false, error: 'Invalid or expired token' });
    }

    if (Date.now() > session.expiresAt) {
      activeSessions.delete(tempToken);
      return reply.send({ success: false, error: 'Code expired' });
    }

    if (session.confirmCode !== code.toString()) {
      return reply.send({ success: false, error: 'Invalid code' });
    }

    // Код верный - создаём полноценную сессию
    const authToken = crypto.randomUUID();
    activeSessions.delete(tempToken);
    activeSessions.set(authToken, {
      user: session.user,
      isPending: false,
      expiresAt: Date.now() + SESSION_DURATION
    });

    return reply.send({
      success: true,
      token: authToken,
      user: {
        nickname: session.user.nickname,
        admin: session.user.admin
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Server error' });
  }
});

// POST /api/logout - выход
fastify.post('/api/logout', async (request, reply) => {
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    activeSessions.delete(token);
  }
  return reply.send({ success: true });
});

// GET /api/verify - проверка токена
fastify.get('/api/verify', async (request, reply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.send({ success: false, valid: false });
  }

  const token = authHeader.substring(7);
  const session = activeSessions.get(token);

  if (!session || session.isPending || Date.now() > session.expiresAt) {
    return reply.send({ success: false, valid: false });
  }

  // Продлеваем сессию
  session.expiresAt = Date.now() + SESSION_DURATION;

  return reply.send({
    success: true,
    valid: true,
    user: session.user
  });
});

// GET /api/logs - ЗАЩИЩЁННЫЙ (с пагинацией)
fastify.get('/api/logs', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const page = Math.max(1, parseInt(request.query.page) || 1);
    const limit = Math.min(1000, Math.max(1, parseInt(request.query.limit) || 150));
    const offset = (page - 1) * limit;
    const type = request.query.type || '';
    const desc = request.query.desc || '';
    const date = request.query.date || '';

    // Получаем общее количество
    let countQuery = "SELECT COUNT(*) as total FROM action_logs";
    let dataQuery = "SELECT id, type, `desc`, DATE_FORMAT(`date`, '%Y-%m-%d') as date, TIME_FORMAT(time, '%H:%i:%s') as time FROM action_logs";

    const conditions = [];
    const params = [];

    // Поддержка фильтрации по типу. "all" означает все типы
    if (type && type !== 'all' && type !== '0') {
      conditions.push("type = ?");
      params.push(type);
    }
    if (desc) {
      conditions.push("`desc` LIKE ?");
      params.push(`%${desc}%`);
    }
    if (date) {
      conditions.push("DATE(`date`) = ?");
      params.push(date);
    }

    if (conditions.length > 0) {
      const whereClause = " WHERE " + conditions.join(" AND ");
      countQuery += whereClause;
      dataQuery += whereClause;
    }

    dataQuery += " ORDER BY id DESC LIMIT ? OFFSET ?";

    const [countRows] = await pool.execute(countQuery, params);
    const [rows] = await pool.execute(dataQuery, [...params, limit.toString(), offset.toString()]);

    return reply.send({
      success: true,
      data: rows,
      total: countRows[0].total,
      page,
      limit,
      totalPages: Math.ceil(countRows[0].total / limit)
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// GET /api/stats - ЗАЩИЩЁННЫЙ
fastify.get('/api/stats', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const [playersRows] = await pool.execute('SELECT COUNT(*) as count FROM players');
    const [configRows] = await pool.execute('SELECT CashStatus FROM Config LIMIT 1');

    const cashStatus = configRows[0]?.CashStatus || 0;
    let cashIn = cashStatus > 0 ? cashStatus : 0;
    let cashOut = cashStatus < 0 ? Math.abs(cashStatus) : 0;

    return reply.send({
      success: true,
      playersCount: playersRows[0].count,
      cashIn,
      cashOut
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// GET /api/player/:nickname - получить информацию об игроке - ЗАЩИЩЁННЫЙ
fastify.get('/api/player/:nickname', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const { nickname } = request.params;

    if (!nickname || typeof nickname !== 'string' || nickname.length > 50) {
      return reply.send({ success: false, error: 'Некорректный никнейм' });
    }

    const [rows] = await pool.execute(
      'SELECT NickName, ID_Telegram FROM players WHERE NickName = ? LIMIT 1',
      [nickname.trim()]
    );

    if (rows.length === 0) {
      return reply.send({ success: false, error: 'Игрок не найден' });
    }

    const player = rows[0];
    return reply.send({
      success: true,
      player: {
        nickname: player.NickName,
        telegram: player.ID_Telegram || 'Не привязан'
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// POST /api/unlink-telegram - отвязать телеграм игрока - ЗАЩИЩЁННЫЙ
fastify.post('/api/unlink-telegram', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const { nickname } = request.body || {};

    if (!nickname || typeof nickname !== 'string' || nickname.length > 50) {
      return reply.send({ success: false, error: 'Некорректный никнейм' });
    }

    // Проверяем существование игрока
    const [rows] = await pool.execute(
      'SELECT NickName FROM players WHERE NickName = ? LIMIT 1',
      [nickname.trim()]
    );

    if (rows.length === 0) {
      return reply.send({ success: false, error: 'Игрок не найден' });
    }

    // Устанавливаем ID_Telegram = -1
    await pool.execute(
      'UPDATE players SET ID_Telegram = -1 WHERE NickName = ?',
      [nickname.trim()]
    );

    fastify.log.info(`Telegram отвязан для игрока: ${nickname} (by ${request.user.nickname})`);

    return reply.send({ success: true });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// GET /api/global-settings - получить глобальные настройки - ЗАЩИЩЁННЫЙ
fastify.get('/api/global-settings', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const [rows] = await pool.execute(
      'SELECT setting_name, setting_value, description FROM global_settings WHERE setting_name = ? LIMIT 1',
      ['logs_limit']
    );

    if (rows.length === 0) {
      // Если настройки нет, создаём с дефолтными значениями
      await pool.execute(
        'INSERT INTO global_settings (setting_name, setting_value, description) VALUES (?, ?, ?)',
        ['logs_limit', 150, 'Глобальный лимит логов на страницу для всех пользователей']
      );

      return reply.send({
        success: true,
        settings: {
          logs_limit: 150
        }
      });
    }

    return reply.send({
      success: true,
      settings: {
        logs_limit: rows[0].setting_value || 150
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// POST /api/global-settings - обновить глобальные настройки - ЗАЩИЩЁННЫЙ
fastify.post('/api/global-settings', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const { logs_limit } = request.body || {};

    // Валидация лимита логов
    const limit = Math.min(1000, Math.max(50, parseInt(logs_limit) || 150));

    // Проверяем существование настройки
    const [existingRows] = await pool.execute(
      'SELECT id FROM global_settings WHERE setting_name = ? LIMIT 1',
      ['logs_limit']
    );

    if (existingRows.length === 0) {
      // Создаём новую настройку
      await pool.execute(
        'INSERT INTO global_settings (setting_name, setting_value, description) VALUES (?, ?, ?)',
        ['logs_limit', limit, 'Глобальный лимит логов на страницу для всех пользователей']
      );
    } else {
      // Обновляем существующую
      await pool.execute(
        'UPDATE global_settings SET setting_value = ? WHERE setting_name = ?',
        [limit, 'logs_limit']
      );
    }

    fastify.log.info(`Глобальные настройки обновлены администратором: ${request.user.nickname} (logs_limit: ${limit})`);

    return reply.send({
      success: true,
      settings: {
        logs_limit: limit
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// GET /api/user-settings - получить настройки (алиас для совместимости)
fastify.get('/api/user-settings', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const [rows] = await pool.execute(
      'SELECT setting_value FROM global_settings WHERE setting_name = ? LIMIT 1',
      ['logs_limit']
    );

    if (rows.length === 0) {
      return reply.send({
        success: true,
        settings: {
          logs_limit: 150
        }
      });
    }

    return reply.send({
      success: true,
      settings: {
        logs_limit: rows[0].setting_value || 150
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// POST /api/user-settings - обновить настройки (алиас для совместимости)
fastify.post('/api/user-settings', { preHandler: authMiddleware }, async (request, reply) => {
  try {
    const { logs_limit } = request.body || {};

    // Валидация лимита логов
    const limit = Math.min(1000, Math.max(50, parseInt(logs_limit) || 150));

    // Проверяем существование настройки
    const [existingRows] = await pool.execute(
      'SELECT id FROM global_settings WHERE setting_name = ? LIMIT 1',
      ['logs_limit']
    );

    if (existingRows.length === 0) {
      // Создаём новую настройку
      await pool.execute(
        'INSERT INTO global_settings (setting_name, setting_value, description) VALUES (?, ?, ?)',
        ['logs_limit', limit, 'Глобальный лимит логов на страницу для всех пользователей']
      );
    } else {
      // Обновляем существующую
      await pool.execute(
        'UPDATE global_settings SET setting_value = ? WHERE setting_name = ?',
        [limit, 'logs_limit']
      );
    }

    fastify.log.info(`Глобальные настройки обновлены администратором: ${request.user.nickname} (logs_limit: ${limit})`);

    return reply.send({
      success: true,
      settings: {
        logs_limit: limit
      }
    });
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ success: false, error: 'Database error' });
  }
});

// Health check (публичный)
fastify.get('/api/health', async () => ({ status: 'ok' }));

// Start
await fastify.listen({ port: process.env.PORT || 3001, host: '0.0.0.0' });
console.log('🚀 Fastify server running');
