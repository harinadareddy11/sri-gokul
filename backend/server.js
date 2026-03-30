const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Config ────────────────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/srigokul';
const JWT_SECRET  = process.env.JWT_SECRET  || 'srigokul_secret_2024';
const PORT        = process.env.PORT        || 5000;

// ─── DB Connection ──────────────────────────────────────────────────────────
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ─── Schemas ────────────────────────────────────────────────────────────────
const OrderSchema = new mongoose.Schema({
  orderNumber: { type: String, unique: true },
  customer: {
    name:         { type: String, required: true },
    phone:        { type: String, required: true },
    address:      { type: String, required: true },
    instructions: { type: String, default: '' },
    latitude:     { type: Number },
    longitude:    { type: Number }
  },
  items: [{
    id:       String,
    name:     String,
    price:    Number,
    quantity: Number,
    comboItems: [{ id: String, name: String }]
  }],
  totalAmount:      { type: Number, required: true },
  deliveryFee:      { type: Number, default: 0 },
  deliveryDistance:  { type: Number },
  status: {
    type: String,
    enum: ['pending', 'preparing', 'completed'],
    default: 'pending'
  },
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

const Order = mongoose.model('Order', OrderSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// ─── Init Default Admin ─────────────────────────────────────────────────────
async function initAdmin() {
  const existing = await Admin.findOne({ username: 'admin' });
  if (!existing) {
    const hashed = await bcrypt.hash('gokul@2024', 10);
    await Admin.create({ username: 'admin', password: hashed });
    console.log('🔐 Default admin created — username: admin  password: gokul@2024');
  }
}
initAdmin();

// ─── Helpers ────────────────────────────────────────────────────────────────
function genOrderNumber() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `SGF${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}${Date.now().toString().slice(-4)}`;
}

// ─── Auth Middleware ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════════════

// Place order
app.post('/api/orders', async (req, res) => {
  try {
    const { customer, items, totalAmount, deliveryFee, deliveryDistance } = req.body;
    if (!customer?.name || !customer?.phone || !customer?.address) {
      return res.status(400).json({ error: 'Missing customer details' });
    }
    if (!items?.length) {
      return res.status(400).json({ error: 'No items in order' });
    }
    const order = await Order.create({
      orderNumber: genOrderNumber(),
      customer,
      items,
      totalAmount,
      deliveryFee: deliveryFee || 0,
      deliveryDistance: deliveryDistance || null
    });
    console.log(`📦 New order: ${order.orderNumber} — ₹${order.totalAmount} (delivery: ₹${order.deliveryFee}) — ${customer.name}`);
    res.status(201).json({ success: true, orderNumber: order.orderNumber, order });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
//  ADMIN AUTH
// ════════════════════════════════════════════════════════════

// Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, admin.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: admin._id, username }, JWT_SECRET, { expiresIn: '24h' });
  console.log(`🔓 Admin login: ${username}`);
  res.json({ token, username });
});

// Change password
app.post('/api/admin/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const admin = await Admin.findById(req.admin.id);
  const valid = await bcrypt.compare(currentPassword, admin.password);
  if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
  admin.password = await bcrypt.hash(newPassword, 10);
  await admin.save();
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════
//  ADMIN – ORDERS
// ════════════════════════════════════════════════════════════

// Get all orders (with optional filters)
app.get('/api/orders', auth, async (req, res) => {
  try {
    const { status, search, sort = 'newest', page = 1, limit = 100 } = req.query;
    const query = {};
    if (status) query.status = status;
    if (search) {
      query.$or = [
        { 'customer.name': { $regex: search, $options: 'i' } },
        { 'customer.phone': { $regex: search } },
        { orderNumber: { $regex: search, $options: 'i' } }
      ];
    }
    const sortMap = {
      newest: { createdAt: -1 },
      oldest: { createdAt: 1 },
      'amount-high': { totalAmount: -1 },
      'amount-low': { totalAmount: 1 }
    };
    const orders = await Order.find(query)
      .sort(sortMap[sort] || { createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single order
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json(order);
});

// Update order status
app.patch('/api/orders/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  if (!['pending', 'preparing', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
  if (!order) return res.status(404).json({ error: 'Order not found' });
  console.log(`📋 Order ${order.orderNumber} → ${status}`);
  res.json(order);
});

// Delete order
app.delete('/api/orders/:id', auth, async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════
//  ADMIN – ANALYTICS
// ════════════════════════════════════════════════════════════

// Full stats
app.get('/api/stats', auth, async (req, res) => {
  try {
    const [total, pending, preparing, completed] = await Promise.all([
      Order.countDocuments(),
      Order.countDocuments({ status: 'pending' }),
      Order.countDocuments({ status: 'preparing' }),
      Order.countDocuments({ status: 'completed' })
    ]);

    const revenueAgg = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);

    // Today's stats
    const todayStart = new Date(); todayStart.setHours(0,0,0,0);
    const todayEnd   = new Date(); todayEnd.setHours(23,59,59,999);
    const todayOrders = await Order.countDocuments({ createdAt: { $gte: todayStart, $lte: todayEnd } });
    const todayRevAgg = await Order.aggregate([
      { $match: { status: 'completed', createdAt: { $gte: todayStart, $lte: todayEnd } } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);

    // Top items
    const topItems = await Order.aggregate([
      { $unwind: '$items' },
      { $group: { _id: '$items.name', count: { $sum: '$items.quantity' }, revenue: { $sum: { $multiply: ['$items.price', '$items.quantity'] } } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // 7-day daily orders
    const sevenDaysAgo = new Date(); sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6); sevenDaysAgo.setHours(0,0,0,0);
    const dailyAgg = await Order.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      { $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 },
          revenue: { $sum: '$totalAmount' }
      }},
      { $sort: { _id: 1 } }
    ]);

    res.json({
      total, pending, preparing, completed,
      revenue: revenueAgg[0]?.total || 0,
      avgOrderValue: completed > 0 ? Math.round((revenueAgg[0]?.total || 0) / completed) : 0,
      completionRate: total > 0 ? Math.round((completed / total) * 100) : 0,
      todayOrders,
      todayRevenue: todayRevAgg[0]?.total || 0,
      topItems,
      dailyStats: dailyAgg
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📋 Admin API ready at http://localhost:${PORT}/api`);
});