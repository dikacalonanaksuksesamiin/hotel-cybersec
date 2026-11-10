const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_cybersec_2026';

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Terlalu banyak percobaan login. Silakan tunggu 15 menit.' }
});

// Database In-Memory
const users = [];
const rooms = [
    { id: 1, name: 'Standard Single Room', price: 350000, status: 'Available', category: 'Standard' },
    { id: 2, name: 'Deluxe Twin Bed', price: 650000, status: 'Available', category: 'Deluxe' },
    { id: 3, name: 'Executive Suite Room', price: 1200000, status: 'Available', category: 'Suite' },
    { id: 4, name: 'Presidential Royal Suite', price: 2500000, status: 'Booked', category: 'Presidential' }
];
const bookings = [];

const sanitizeInput = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/[<>'"]/g, '');
};

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak. Silakan login.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token tidak valid.' });
        req.user = user;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Akses terlarang! Hanya untuk Admin.' });
        }
        next();
    };
};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username);
        const name = sanitizeInput(req.body.name || username);
        const password = req.body.password;
        const role = req.body.role === 'admin' ? 'admin' : 'customer';

        if (!username || !password || password.length < 6) {
            return res.status(400).json({ error: 'Username & Password minimal 6 karakter!' });
        }

        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username sudah terdaftar.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ id: users.length + 1, username, name, password: hashedPassword, role });
        res.status(201).json({ message: 'Registrasi berhasil! Silakan login.' });
    } catch (err) {
        res.status(500).json({ error: 'Gagal memproses registrasi.' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    const username = sanitizeInput(req.body.username);
    const password = req.body.password;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'Username atau password salah.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Username atau password salah.' });

    const token = jwt.sign({ id: user.id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '2h' });

    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7200000
    });

    res.json({ message: 'Login berhasil!', role: user.role, username: user.username, name: user.name });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout berhasil.' });
});

// Stats & Dashboard
app.get('/api/stats', authenticateToken, (req, res) => {
    const categories = new Set(rooms.map(r => r.category)).size;
    const totalCustomers = users.filter(u => u.role === 'customer').length;
    res.json({
        totalRooms: rooms.length,
        totalCategories: categories,
        totalCustomers: totalCustomers,
        totalTransactions: bookings.length
    });
});

// Rooms CRUD
app.get('/api/rooms', authenticateToken, (req, res) => {
    res.json(rooms);
});

app.post('/api/rooms/add', authenticateToken, requireRole('admin'), (req, res) => {
    const name = sanitizeInput(req.body.name);
    const category = sanitizeInput(req.body.category || 'Standard');
    const price = parseInt(req.body.price);

    const newRoom = { id: rooms.length + 1, name, category, price, status: 'Available' };
    rooms.push(newRoom);
    res.status(201).json({ message: 'Kamar berhasil ditambahkan.', room: newRoom });
});

app.delete('/api/rooms/:id', authenticateToken, requireRole('admin'), (req, res) => {
    const id = parseInt(req.params.id);
    const index = rooms.findIndex(r => r.id === id);
    if (index !== -1) {
        rooms.splice(index, 1);
        return res.json({ message: 'Data kamar berhasil dihapus.' });
    }
    res.status(404).json({ error: 'Kamar tidak ditemukan.' });
});

// Bookings
app.get('/api/bookings', authenticateToken, (req, res) => {
    if (req.user.role === 'admin') {
        res.json(bookings);
    } else {
        res.json(bookings.filter(b => b.userId === req.user.id));
    }
});

app.post('/api/bookings', authenticateToken, (req, res) => {
    const roomId = parseInt(req.body.roomId);
    const checkInDate = sanitizeInput(req.body.checkInDate);

    const room = rooms.find(r => r.id === roomId);
    if (!room || room.status !== 'Available') {
        return res.status(400).json({ error: 'Kamar tidak tersedia.' });
    }

    const newBooking = {
        id: bookings.length + 1,
        userId: req.user.id,
        username: req.user.username,
        roomName: room.name,
        price: room.price,
        checkInDate,
        createdAt: new Date().toLocaleDateString('id-ID')
    };

    bookings.push(newBooking);
    res.status(201).json({ message: 'Pemesanan kamar berhasil dibuat!', booking: newBooking });
});

// Customers list for Admin
app.get('/api/customers', authenticateToken, requireRole('admin'), (req, res) => {
    const customerList = users.filter(u => u.role === 'customer').map(u => ({ id: u.id, username: u.username, name: u.name }));
    res.json(customerList);
});

// Reports & Export
app.get('/api/reports/recap', authenticateToken, requireRole('admin'), (req, res) => {
    const totalIncome = bookings.reduce((sum, b) => sum + b.price, 0);
    res.json({ totalBookings: bookings.length, totalIncome: totalIncome, details: bookings });
});

app.get('/api/reports/export-csv', authenticateToken, requireRole('admin'), (req, res) => {
    let csv = 'ID Transaksi,Username,Kamar,Harga,Tanggal CheckIn\n';
    bookings.forEach(b => {
        csv += `${b.id},${b.username},${b.roomName},${b.price},${b.checkInDate}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=Laporan_Transaksi_Hotel.csv');
    res.send(csv);
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
}

module.exports = app;