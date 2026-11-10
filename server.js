const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_cybersec_2026';

// 1. Keamanan Middleware
app.use(helmet()); // Mengaktifkan Security Headers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Rate Limiter untuk mencegah brute force pada login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 10, // Maksimal 10 percobaaan per IP
    message: { error: 'Terlalu banyak percobaan login. Coba lagi nanti.' }
});

// Database In-Memory (Simulasi Database Aman)
const users = [];       // Data Pengguna (Hashed Password)
const rooms = [         // Data Kamar (CRUD)
    { id: 1, name: 'Deluxe Room', price: 500000, status: 'Available' },
    { id: 2, name: 'Suite Room', price: 1000000, status: 'Available' }
];
const bookings = [];    // Data Reservasi

// Middleware Sanitasi Input Sederhana (Cegah XSS/Injection)
const sanitizeInput = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/[<>'"]/g, '');
};

// Middleware Autentikasi & RBAC (Role Access Control)
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak. Silakan login.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token tidak valid atau kadaluwarsa.' });
        req.user = user;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Akses terlarang! Anda bukan Admin.' });
        }
        next();
    };
};

// --- ENDPOINT AUTENTIKASI ---

// Registrasi User / Admin[cite: 1]
app.post('/api/register', async (req, res) => {
    try {
        const username = sanitizeInput(req.body.username);
        const password = req.body.password;
        const role = req.body.role === 'admin' ? 'admin' : 'customer';

        if (!username || !password || password.length < 6) {
            return res.status(400).json({ error: 'Username & Password minimal 6 karakter!' });
        }

        const existingUser = users.find(u => u.username === username);
        if (existingUser) return res.status(400).json({ error: 'Username sudah digunakan.' });

        // Hash Password menggunakan Bcrypt[cite: 1]
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ id: users.length + 1, username, password: hashedPassword, role });

        res.status(201).json({ message: 'Registrasi berhasil! Silakan login.' });
    } catch (err) {
        res.status(500).json({ error: 'Gagal memproses registrasi.' });
    }
});

// Login User[cite: 1, 2]
app.post('/api/login', loginLimiter, async (req, res) => {
    const username = sanitizeInput(req.body.username);
    const password = req.body.password;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'Username atau password salah.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Username atau password salah.' });

    // Generate JWT Token & Set di HttpOnly Cookie
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, {
        httpOnly: true, // Tidak bisa diakses via JavaScript Browser (Cegah XSS Cookie Theft)
        secure: process.env.NODE_ENV === 'production', // Wajib HTTPS saat terdeploy
        sameSite: 'strict',
        maxAge: 3600000
    });

    res.json({ message: 'Login berhasil!', role: user.role, username: user.username });
});

// Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout berhasil.' });
});

// --- ENDPOINT FITUR CRUD (Pemesanan & Kamar) ---[cite: 1]

// Read: Lihat Daftar Kamar (Publik/User)
app.get('/api/rooms', authenticateToken, (req, res) => {
    res.json(rooms);
});

// Create: Buat Pemesanan Kamar (Customer)[cite: 1]
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
        createdAt: new Date().toISOString()
    };

    bookings.push(newBooking);
    res.status(201).json({ message: 'Pemesanan kamar berhasil!', booking: newBooking });
});

// Update & Delete: Admin Only (CRUD Kamar)[cite: 1, 2]
app.post('/api/rooms/add', authenticateToken, requireRole('admin'), (req, res) => {
    const name = sanitizeInput(req.body.name);
    const price = parseInt(req.body.price);

    const newRoom = { id: rooms.length + 1, name, price, status: 'Available' };
    rooms.push(newRoom);
    res.status(201).json({ message: 'Kamar berhasil ditambahkan.', room: newRoom });
});

// --- ENDPOINT LAPORAN (Rekapitulasi Data) ---[cite: 1]

// Laporan Rekap Pemesanan (Admin Only)[cite: 1, 2]
app.get('/api/reports/recap', authenticateToken, requireRole('admin'), (req, res) => {
    const totalIncome = bookings.reduce((sum, b) => sum + b.price, 0);
    res.json({
        totalBookings: bookings.length,
        totalIncome: totalIncome,
        details: bookings
    });
});

// Ekspor Laporan CSV (Nilai Tambah Tugas)[cite: 1]
app.get('/api/reports/export-csv', authenticateToken, requireRole('admin'), (req, res) => {
    let csv = 'ID,Username,Kamar,Harga,Tanggal\n';
    bookings.forEach(b => {
        csv += `${b.id},${b.username},${b.roomName},${b.price},${b.checkInDate}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=rekap-pemesanan.csv');
    res.send(csv);
});

app.listen(PORT, () => {
    console.log(`Server Hotel Booking berjalan di port ${PORT}`);
});