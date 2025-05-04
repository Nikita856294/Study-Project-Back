const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
const app = express();
app.use(cors());
app.use(express.json());

const corsOptions = {
    origin: ['http://localhost:5173', 'https://your-frontend-domain'], // Добавьте URL деплоя фронтенда позже
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

const dbConfig = {
    
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'your_username',
    password: process.env.DB_PASSWORD || 'your_password',
    database: process.env.DB_NAME || 'Nikitenko'
};


const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';


const PORT = process.env.PORT || 3000;

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Токен отсутствует' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Недействительный токен' });
        req.user = user;
        next();
    });
};


async function initDb() {
    const connection = await mysql.createConnection(dbConfig);
    await connection.execute(`
        CREATE TABLE IF NOT EXISTS Users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
    `);
    await connection.end();
}

initDb().catch(err => console.error('Ошибка инициализации базы данных:', err));


app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });

    const connection = await mysql.createConnection(dbConfig);
    const [users] = await connection.execute('SELECT * FROM Users WHERE username = ?', [username]);
    if (users.length > 0) return res.status(400).json({ error: 'Пользователь уже существует' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await connection.execute('INSERT INTO Users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    await connection.end();
    res.json({ message: 'Пользователь зарегистрирован' });
});


app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });

    const connection = await mysql.createConnection(dbConfig);
    const [users] = await connection.execute('SELECT * FROM Users WHERE username = ?', [username]);
    await connection.end();

    if (users.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });
    const user = users[0];

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Неверный пароль' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});


app.get('/api/:table', authenticateToken, async (req, res) => {
    const { table } = req.params;
    const { sortBy, order, filterRole, search } = req.query;
    const validTables = ['crew', 'supplies', 'repairs', 'experiments', 'alienEncounters'];
    if (!validTables.includes(table)) return res.status(400).json({ error: 'Недопустимая таблица' });

    let query = `SELECT * FROM ${table}`;
    const params = [];

    if (sortBy && order) {
        query += ` ORDER BY ${mysql.escapeId(sortBy)} ${order}`;
    }
    if (filterRole && table === 'crew') {
        query += ` WHERE role = ?`;
        params.push(filterRole);
    }
    if (search) {
        query += ` WHERE ${table === 'crew' ? 'first_name' : 'supply_type'} LIKE ?`;
        params.push(`%${search}%`);
    }

    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(query, params);
    await connection.end();
    res.json(rows);
});


app.post('/api/:table', authenticateToken, async (req, res) => {
    const { table } = req.params;
    const validTables = ['crew', 'supplies', 'repairs', 'experiments', 'alienEncounters'];
    if (!validTables.includes(table)) return res.status(400).json({ error: 'Недопустимая таблица' });

    const connection = await mysql.createConnection(dbConfig);
    const fields = Object.keys(req.body).join(', ');
    const placeholders = Object.keys(req.body).map(() => '?').join(', ');
    const values = Object.values(req.body);

    await connection.execute(`INSERT INTO ${table} (${fields}) VALUES (${placeholders})`, values);
    await connection.end();
    res.json({ message: 'Данные добавлены' });
});


app.get('/api/queries/oxygen', authenticateToken, async (req, res) => {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
        SELECT s.supply_id, s.quantity AS current_quantity, 
               s.quantity - (SELECT COALESCE(SUM(r.quantity_used), 0) 
                             FROM Repairs r 
                             WHERE r.supply_id = s.supply_id) AS remaining_oxygen
        FROM Supplies s
        WHERE s.supply_type = 'Oxygen'
    `);
    await connection.end();
    res.json(rows);
});

app.get('/api/queries/repairs', authenticateToken, async (req, res) => {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
        SELECT c.first_name, c.last_name, COUNT(r.repair_id) AS repair_count
        FROM Crew c
        LEFT JOIN Repairs r ON c.crew_id = r.crew_id
        GROUP BY c.crew_id, c.first_name, c.last_name
        ORDER BY repair_count DESC
    `);
    await connection.end();
    res.json(rows);
});

app.get('/api/queries/systems', authenticateToken, async (req, res) => {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
        SELECT system_name, COUNT(repair_id) AS repair_count
        FROM Repairs
        GROUP BY system_name
        ORDER BY repair_count DESC
        LIMIT 1
    `);
    await connection.end();
    res.json(rows);
});


app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});