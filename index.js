const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(cookieParser());

app.use(cors({
    origin: 'http://localhost:3000', 
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));

app.use(bodyParser.json());

const SECRET_KEY = 'secret-key';
const users = [];
const sessions = {}; 
const CACHE_FILE = path.join(__dirname, 'cache.json');
const CACHE_TTL = 60000; 

function readCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const cacheData = fs.readFileSync(CACHE_FILE, 'utf8');
      return JSON.parse(cacheData);
    }
  } catch (err) {
    console.error('Error reading cache:', err);
  }
  return null;
}

function writeCache(data) {
  try {
    const cacheData = {
      data,
      timestamp: Date.now()
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cacheData));
  } catch (err) {
    console.error('Error writing cache:', err);
  }
}

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = 
        req.cookies?.token || 
        (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null);
    
    if (!token) {
        return res.status(403).json({ message: 'Требуется токен' });
    }
  
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Неверный токен' });
        }
        
        if (!sessions[decoded.username]) {
            return res.status(401).json({ message: 'Сессия не найдена' });
        }
        
        req.user = decoded;
        next();
    });
  }

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  
  if (users.some(u => u.username === username)) {
    return res.status(400).json({ message: 'Имя занято' });
  }
  
  users.push({ username, email, password });
  res.json({ message: 'Пользователь успешно зарегистрирован' });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
      const tokenPayload = { 
        username: user.username,
        iat: Math.floor(Date.now() / 1000) 
      };
      
      const token = jwt.sign(
        tokenPayload,
        SECRET_KEY,
        { expiresIn: '1h' }
      );
      
      console.log('Generated token payload:', tokenPayload);
      
      sessions[user.username] = {
        token,
        lastActive: Date.now()
      };
      
      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'lax', 
        maxAge: 3600000,
      });
      
      res.json({ 
        message: 'Вход выполнен успешно',
        username: user.username,
        token 
      });
    } else {
      res.status(401).json({ message: 'Неправильные данные для входа' });
    }
  });

app.post('/logout', verifyToken, (req, res) => {
    if (!req.user || !req.user.username) {
      return res.status(400).json({ message: 'Не удалось определить пользователя' });
    }
    
    delete sessions[req.user.username];
    
    res.clearCookie('token', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    
    res.json({ message: 'Выход выполнен успешно' });
  });
  
app.get('/profile', verifyToken, (req, res) => {
    const user = users.find(u => u.username === req.user.username);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const { password, ...userData } = user;
    res.json({ 
      message: 'Profile data',
      user: userData
    });
  });


app.get('/data', verifyToken, (req, res) => {

  const cache = readCache();
  
  if (cache && (Date.now() - cache.timestamp < CACHE_TTL)) {
    return res.json({
      message: 'Данные из кэша',
      data: cache.data,
      cached: true
    });
  }
  
  const newData = {
    items: [
      { id: 1, name: 'Элемент 1', value: Math.random() },
      { id: 2, name: 'Элемент 2', value: Math.random() },
      { id: 3, name: 'Элемент 3', value: Math.random() }
    ],
    generatedAt: new Date().toISOString()
  };
  
  writeCache(newData);
  
  res.json({
    message: 'Новые данные',
    data: newData,
    cached: false
  });
});

setInterval(() => {
  const now = Date.now();
  Object.keys(sessions).forEach(userId => {
    if (now - sessions[userId].lastActive > 3600000) { // 1 hour
      delete sessions[userId];
    }
  });
}, 60000);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

app.listen(3000, () => console.log('Сервер запущен на http://localhost:3000'));