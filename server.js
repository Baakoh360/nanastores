// server.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const fetch = require('node-fetch');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

// Initialize express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Serve robots.txt and sitemap.xml with minimal caching to avoid stale search engine data
app.get('/robots.txt', (req, res) => {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
});

// Sessions for admin auth (initialized after MONGODB_URI is available)

// Check for required environment variables
const requiredEnvVars = [
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'MONGODB_URI'
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        console.error('Please check your .env file and ensure all required variables are set.');
        process.exit(1);
    }
}

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Test Cloudinary connection
cloudinary.api.ping()
    .then(() => console.log('Cloudinary connected successfully'))
    .catch(err => {
        console.error('Cloudinary connection failed:', err);
        console.error('Please check your Cloudinary credentials in the .env file');
    });

// Configure Cloudinary storage for multer
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'product-images',
        allowed_formats: ['jpeg', 'jpg', 'png', 'gif']
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function(req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Connect to MongoDB Atlas
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log('MongoDB Atlas connected'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// Initialize session store now that MONGODB_URI is defined
app.use(session({
    secret: process.env.SESSION_SECRET || 'change_this_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 },
    store: MongoStore.create({ mongoUrl: MONGODB_URI })
}));

// Product Schema and Model
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    oldPrice: { type: Number },
    category: { type: String, required: true },
    description: { type: String },
    imageUrl: { type: String },
    publicId: { type: String }, // To store Cloudinary public_id for deletions
    stock: { type: Number, default: 0, min: 0 }, // Stock quantity
    inStock: { type: Boolean, default: true }, // Computed from stock > 0
    sizes: { type: [Number], default: undefined }, // optional sizes
    createdAt: { type: Date, default: Date.now }
});

// Virtual to automatically set inStock based on stock
productSchema.virtual('isAvailable').get(function() {
    return this.stock > 0;
});

// Pre-save hook to update inStock based on stock
productSchema.pre('save', function(next) {
    this.inStock = this.stock > 0;
    next();
});

const Product = mongoose.model('Product', productSchema);

// Order Schema and Model
const orderItemSchema = new mongoose.Schema({
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true },
    size: { type: Number },
    color: { type: String }
});

const orderSchema = new mongoose.Schema({
    orderNumber: { 
        type: String, 
        unique: true,
        sparse: true // Allows null values without causing duplicate key errors
    },
    customer: {
        name: { type: String, required: true },
        phone: { type: String, required: true },
        email: { type: String, required: true },
        location: { type: String, required: true },
        notes: { type: String }
    },
    items: { type: [orderItemSchema], required: true },
    subtotal: { type: Number, required: true },
    fee: { type: Number, default: 0 },
    total: { type: Number, required: true },
    payment: {
        provider: { type: String, default: 'paystack' },
        reference: { type: String },
        status: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' }
    },
    status: { type: String, enum: ['new', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'new' }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

// Helper: parse sizes string/array into number array (supports lists and ranges)
function parseSizesField(input) {
    if (Array.isArray(input)) {
        return input
            .map(n => parseInt(n, 10))
            .filter(n => !isNaN(n));
    }
    if (typeof input !== 'string') return undefined;
    const trimmed = input.trim();
    if (!trimmed) return undefined;
    // Expand ranges like "40-43" or "40 to 43"
    // Support ASCII hyphen-minus and Unicode en/em dashes
    const rangeMatch = trimmed.match(/^(\d{1,3})\s*(?:-|–|—|to)\s*(\d{1,3})$/i);
    if (rangeMatch) {
        const start = parseInt(rangeMatch[1], 10);
        const end = parseInt(rangeMatch[2], 10);
        if (!isNaN(start) && !isNaN(end) && end >= start) {
            const out = [];
            for (let s = start; s <= end; s++) out.push(s);
            return out;
        }
    }
    // Split on commas or whitespace for list
    return trimmed
        .split(/[\s,]+/)
        .map(s => parseInt(s, 10))
        .filter(n => !isNaN(n));
}

// SMS Notification helper - sends SMS notifications only
async function sendNotification(customer, message, type = 'order') {
    try {
        // Send SMS only
        if (customer.phone) {
            await sendSMS(customer.phone, message);
        } else {
            console.error('❌ No phone number provided for SMS notification');
        }
    } catch (e) {
        console.error('❌ SMS notification error:', e.message);
    }
}

// Helper: extract color from a product description string
function parseColorFromDescription(description) {
    try {
        if (!description || typeof description !== 'string') return null;
        const text = description.toLowerCase();

        // 1) Try labeled patterns like: "color: Red", "colour - Navy Blue", "color=wine red", or "color blue"
        // Allow hyphens, numbers, slashes & plus for combinations
        const labelMatch = text.match(/colou?r\s*(?:[:\-=]?\s*)([a-z0-9\-\s\/&+]+)/i);
        if (labelMatch && labelMatch[1]) {
            const raw = labelMatch[1].trim();
            // Stop at common delimiters or next label like size
            const cleaned = raw.split(/\.|,|;|\n|\(|\)|\[|\]|\||\*|\bsize\b|\bquantity\b|\bqty\b/i)[0].trim();
            if (cleaned) {
                // If multi options like "black/white", choose the first as primary color
                const primary = cleaned.split(/[\/|&+]/)[0].trim();
                return primary ? primary.replace(/\s+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : null;
            }
        }

        // 2) Fallback: search for known color names anywhere in text
        const COLORS = [
            'black','white','red','blue','green','yellow','orange','purple','pink','brown','grey','gray',
            'navy','navy blue','sky blue','light blue','dark blue','maroon','beige','cream','gold','silver',
            'teal','turquoise','magenta','violet','indigo','burgundy','khaki','olive'
        ];
        for (const c of COLORS.sort((a,b)=>b.length-a.length)) {
            const re = new RegExp(`\\b${c.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}\\b`, 'i');
            if (re.test(text)) {
                return c.replace(/\b\w/g, x => x.toUpperCase());
            }
        }
        return null;
    } catch (e) {
        return null;
    }
}

// SMS helper (optional env config)
async function sendSMS(toPhone, text) {
    try {
        const provider = process.env.SMS_PROVIDER || 'none';
        console.log(`📱 Attempting to send SMS to ${toPhone} via ${provider}`);
        
        if (provider === 'twilio') {
            const sid = process.env.TWILIO_ACCOUNT_SID;
            const token = process.env.TWILIO_AUTH_TOKEN;
            const from = process.env.TWILIO_FROM;
            
            if (!sid || !token || !from) {
                console.error('❌ Twilio credentials missing! Check SMS_PROVIDER, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM in .env');
                return;
            }
            
            // Ensure phone number is in international format
            let formattedPhone = toPhone.trim();
            if (!formattedPhone.startsWith('+')) {
                // If it starts with 0, replace with country code
                if (formattedPhone.startsWith('0')) {
                    formattedPhone = '+233' + formattedPhone.substring(1);
                } else if (formattedPhone.startsWith('233')) {
                    formattedPhone = '+' + formattedPhone;
                } else {
                    // Assume Ghana number
                    formattedPhone = '+233' + formattedPhone;
                }
            }
            
            console.log(`📤 Sending SMS via Twilio to ${formattedPhone} from ${from}`);
            
            const auth = Buffer.from(`${sid}:${token}`).toString('base64');
            const body = new URLSearchParams({ 
                To: formattedPhone, 
                From: from, 
                Body: text 
            });
            
            const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
                method: 'POST',
                headers: { 
                    'Authorization': `Basic ${auth}`, 
                    'Content-Type': 'application/x-www-form-urlencoded' 
                },
                body
            });
            
            const responseData = await response.json();
            
            if (response.ok && responseData.sid) {
                console.log(`✅ SMS sent successfully! SID: ${responseData.sid}`);
                console.log(`   To: ${formattedPhone}`);
                console.log(`   Message: ${text.substring(0, 50)}...`);
            } else {
                console.error('❌ Twilio API error:', responseData);
                console.error(`   Status: ${response.status}`);
                console.error(`   Error: ${responseData.message || 'Unknown error'}`);
            }
        } else {
            // Not configured, just log
            console.log('📱 SMS (mock mode - not actually sent):');
            console.log(`   To: ${toPhone}`);
            console.log(`   Message: ${text}`);
        }
    } catch (e) {
        console.error('❌ SMS send error:', e.message);
        console.error('   Stack:', e.stack);
    }
}

// Auth middleware
function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) return next();
    return res.status(401).json({ message: 'Unauthorized' });
}

// Admin auth routes
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    const systemPassword = process.env.ADMIN_PASSWORD;
    if (!systemPassword) {
        return res.status(500).json({ message: 'Admin password not configured' });
    }
    if (!password) return res.status(400).json({ message: 'Password is required' });
    if (password === systemPassword) {
        req.session.isAdmin = true;
        return res.json({ success: true });
    }
    return res.status(401).json({ message: 'Invalid password' });
});

app.post('/api/admin/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// API Routes

// Get all products
app.get('/api/products', async(req, res) => {
    try {
        // For public API, only show products with stock > 0
        // Admin can see all products via /api/admin/products
        const products = await Product.find({ stock: { $gt: 0 } }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: 'Failed to fetch products' });
    }
});

// Create order (public) - SIMPLIFIED AND CLEAN
app.post('/api/orders', async(req, res) => {
    try {
        const { customer, items } = req.body;
        
        // Basic validation
        if (!customer || !items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ message: 'Customer info and items are required' });
        }
        
        if (!customer.name || !customer.phone || !customer.email || !customer.location) {
            return res.status(400).json({ message: 'All customer fields are required' });
        }

        // Process items and check stock availability
        let subtotal = 0;
        const orderItems = [];
        const stockUpdates = []; // Track stock updates
        
        for (const item of items) {
            if (!item.id || !item.quantity) continue;
            
            const product = await Product.findById(item.id);
            if (!product) continue;
            
            const quantity = parseInt(item.quantity) || 1;
            
            // Check stock availability
            if (product.stock < quantity) {
                return res.status(400).json({ 
                    message: `Insufficient stock for ${product.name}. Available: ${product.stock}, Requested: ${quantity}` 
                });
            }
            
            const price = parseFloat(product.price) || 0;
            // Derive color from product description if present, allow client-provided override
            const clientColor = typeof item.color === 'string' ? item.color.trim() : null;
            const derivedColor = parseColorFromDescription(product.description);
            if (!clientColor && derivedColor) {
                console.log('Derived color for product', product.name, '=>', derivedColor, '\nDescription:', product.description);
            }
            const lineTotal = price * quantity;
            
            subtotal += lineTotal;
            orderItems.push({
                productId: product._id,
                name: product.name,
                price: price,
                quantity: quantity,
                size: item.size ? parseInt(item.size) : undefined,
                color: (clientColor || derivedColor) || undefined
            });
            
            // Track stock reduction
            stockUpdates.push({
                productId: product._id,
                quantity: quantity
            });
        }
        
        if (orderItems.length === 0) {
            return res.status(400).json({ message: 'No valid items found' });
        }

        // Calculate total (add GH₵1 fee)
        const fee = 1.00;
        const total = subtotal + fee;

        // Generate unique order number with retry logic
        let order;
        let attempts = 0;
        const maxAttempts = 5;
        
        while (attempts < maxAttempts) {
            try {
                const orderNumber = `NBS-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
                
                // Create order
                order = await Order.create({
                    orderNumber: orderNumber,
                    customer: {
                        name: customer.name.trim(),
                        phone: customer.phone.trim(),
                        email: customer.email.trim(),
                        location: customer.location.trim(),
                        notes: customer.notes ? customer.notes.trim() : ''
                    },
                    items: orderItems,
                    subtotal: parseFloat(subtotal.toFixed(2)),
                    fee: fee,
                    total: parseFloat(total.toFixed(2)),
                    payment: { status: 'pending' }
                });
                
                console.log('✅ Order created successfully:', {
                    id: order._id,
                    orderNumber: order.orderNumber,
                    customer: order.customer.name,
                    total: order.total,
                    itemsCount: order.items.length
                });
                
                // Success - break out of loop
                break;
            } catch (createError) {
                attempts++;
                
                // If it's a duplicate key error and we haven't exceeded max attempts, retry
                if (createError.code === 11000 && attempts < maxAttempts) {
                    // Wait a bit before retrying (to ensure different timestamp)
                    await new Promise(resolve => setTimeout(resolve, 100));
                    continue;
                }
                
                // If it's not a duplicate key error or we've exceeded attempts, throw
                throw createError;
            }
        }
        
        if (!order) {
            throw new Error('Failed to create order after multiple attempts');
        }

        // Reduce stock for all ordered items
        for (const update of stockUpdates) {
            try {
                await Product.findByIdAndUpdate(
                    update.productId,
                    { $inc: { stock: -update.quantity } },
                    { new: true }
                );
                console.log(`✅ Reduced stock for product ${update.productId} by ${update.quantity}`);
            } catch (stockError) {
                console.error(`❌ Error reducing stock for product ${update.productId}:`, stockError.message);
            }
        }

        // Send notifications via Email, WhatsApp, SMS (multi-channel)
        try {
            const itemsList = orderItems.map(i => `${i.name}${i.size ? ' [size ' + i.size + ']' : ''}${i.color ? ' [' + i.color + ']' : ''} (x${i.quantity})`).join(', ');
            const message = `NANA BAAKO STORES: Order received! Items: ${itemsList}. Total: GH₵${total.toFixed(2)}. Please complete payment.`;
            sendNotification(customer, message, 'order');
        } catch (notifError) {
            // Ignore notification errors
            console.error('Notification error:', notifError.message);
        }

        res.status(201).json(order);
    } catch (error) {
        console.error('Order creation error:', error.message);
        res.status(500).json({ message: 'Failed to create order: ' + error.message });
    }
});

// Initialize Paystack transaction - SIMPLIFIED
app.post('/api/paystack/initialize', async (req, res) => {
    try {
        const { orderId, email } = req.body;
        
        if (!orderId || !email) {
            return res.status(400).json({ message: 'Order ID and email are required' });
        }

        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }

        // Convert total to pesewas (Paystack expects amount in smallest currency unit)
        const amountInPesewas = Math.round(order.total * 100);

        const response = await fetch('https://api.paystack.co/transaction/initialize', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                amount: amountInPesewas,
                reference: `NBS-${order._id}-${Date.now()}`,
                callback_url: `${req.protocol}://${req.get('host')}/api/paystack/callback`
            })
        });

        const data = await response.json();

        if (!data.status) {
            return res.status(400).json({ message: data.message || 'Failed to initialize payment' });
        }

        // Save payment reference
        order.payment.reference = data.data.reference;
        await order.save();

        res.json({
            authorization_url: data.data.authorization_url,
            reference: data.data.reference
        });

    } catch (error) {
        console.error('Paystack init error:', error.message);
        res.status(500).json({ message: 'Failed to initialize payment: ' + error.message });
    }
});

// Paystack callback - SIMPLIFIED
app.get('/api/paystack/callback', async (req, res) => {
    try {
        const { reference } = req.query;
        if (!reference) {
            return res.redirect('/?payment=error');
        }

        // Verify payment
        const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
            headers: { 'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });
        
        const verifyData = await verifyRes.json();

        if (verifyData.status && verifyData.data.status === 'success') {
            const order = await Order.findOne({ 'payment.reference': reference });
            if (order && order.payment.status !== 'paid') {
                order.payment.status = 'paid';
                await order.save();
                
                // Send notifications via Email, WhatsApp, SMS
                try {
                    const itemsList = order.items.map(i => `${i.name}${i.size ? ' [size ' + i.size + ']' : ''} (x${i.quantity})`).join(', ');
                    const message = `NANA BAAKO STORES: Payment confirmed! Order for ${itemsList} is being processed.`;
                    sendNotification(order.customer, message, 'order');
                } catch (notifError) {
                    // Ignore notification errors
                    console.error('Notification error:', notifError.message);
                }
            }
            return res.redirect('/?payment=success');
        }
        
        return res.redirect('/?payment=failed');
    } catch (error) {
        console.error('Callback error:', error.message);
        return res.redirect('/?payment=error');
    }
});

// Paystack webhook - SIMPLIFIED
app.post('/api/paystack/webhook', express.json({ type: '*/*' }), async (req, res) => {
    try {
        const signature = req.headers['x-paystack-signature'];
        const secret = process.env.PAYSTACK_SECRET_KEY;
        
        if (!secret) {
            return res.sendStatus(500);
        }

        // Verify signature
        const hash = crypto.createHmac('sha512', secret).update(JSON.stringify(req.body)).digest('hex');
        
        if (hash !== signature) {
            return res.sendStatus(401);
        }

        // Handle successful payment
        if (req.body.event === 'charge.success') {
            const reference = req.body.data.reference;
            const order = await Order.findOne({ 'payment.reference': reference });
            
            if (order && order.payment.status !== 'paid') {
                order.payment.status = 'paid';
                await order.save();
                
                // Send notifications via Email, WhatsApp, SMS
                try {
                    const itemsList = order.items.map(i => `${i.name} (x${i.quantity})`).join(', ');
                    const message = `NANA BAAKO STORES: Payment confirmed! Order for ${itemsList} is being processed.`;
                    sendNotification(order.customer, message, 'order');
                } catch (notifError) {
                    // Ignore notification errors
                    console.error('Notification error:', notifError.message);
                }
            }
        }
        
        res.sendStatus(200);
    } catch (error) {
        console.error('Webhook error:', error.message);
        res.sendStatus(500);
    }
});

// Admin: update order status and notify customer
app.put('/api/admin/orders/:id/status', requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const valid = ['new', 'processing', 'shipped', 'delivered', 'cancelled'];
        if (!valid.includes(status)) return res.status(400).json({ message: 'Invalid status' });
        const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!order) return res.status(404).json({ message: 'Order not found' });

        let text;
        const orderItems = order.items.map(i => `${i.name}${i.size ? ' [size ' + i.size + ']' : ''} (x${i.quantity})`).join(', ');
        if (status === 'processing') {
            text = `Your order for ${orderItems} is now being processed. We're preparing your items for shipment.`;
        } else if (status === 'shipped') {
            text = `Great news! Your order for ${orderItems} has been shipped. It's on its way to ${order.customer.location}. You'll receive it soon!`;
        } else if (status === 'delivered') {
            text = `Your order for ${orderItems} has been delivered to ${order.customer.location}. Thank you for shopping with NANA BAAKO STORES!`;
        } else if (status === 'cancelled') {
            text = `Your order for ${orderItems} has been cancelled. If you have questions, please contact us.`;
        }
        if (text) {
            sendNotification(order.customer, `NANA BAAKO STORES: ${text}`, 'order');
        }

        res.json(order);
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Failed to update order status' });
    }
});

// Test endpoint to check orders (remove in production)
app.get('/api/test/orders', async(req, res) => {
    try {
        const count = await Order.countDocuments();
        const recentOrders = await Order.find().sort({ createdAt: -1 }).limit(5);
        res.json({ 
            totalOrders: count,
            recentOrders: recentOrders.map(o => ({
                id: o._id,
                orderNumber: o.orderNumber,
                customer: o.customer.name,
                phone: o.customer.phone,
                total: o.total,
                createdAt: o.createdAt
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Test endpoint to test SMS (remove in production)
app.post('/api/test/sms', async(req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) {
            return res.status(400).json({ error: 'Phone number required' });
        }
        
        const testMessage = 'NANA BAAKO STORES: Test SMS. If you receive this, SMS is working correctly!';
        await sendSMS(phone, testMessage);
        
        res.json({ 
            success: true, 
            message: 'SMS test initiated. Check server logs and your phone.',
            phone: phone,
            provider: process.env.SMS_PROVIDER || 'none'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin: list orders
app.get('/api/admin/orders', requireAdmin, async(req, res) => {
    try {
        console.log('Fetching orders for admin...');
        const orders = await Order.find().sort({ createdAt: -1 });
        console.log(`Found ${orders.length} orders`);
        console.log('Orders:', orders.map(o => ({
            id: o._id,
            orderNumber: o.orderNumber,
            customer: o.customer.name,
            total: o.total,
            paymentStatus: o.payment?.status
        })));
        res.json(orders);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});

// Admin: delete order
app.delete('/api/admin/orders/:id', requireAdmin, async(req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        await Order.findByIdAndDelete(req.params.id);
        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        console.error('Error deleting order:', error);
        res.status(500).json({ message: 'Failed to delete order', error: error.message });
    }
});

// Admin: download orders as formatted receipts (HTML)
app.get('/api/admin/orders/download', requireAdmin, async(req, res) => {
    try {
        const orders = await Order.find().sort({ createdAt: -1 });
        
        // Create receipt HTML template
        const receiptHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orders Receipt - NANA BAAKO STORES</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        @media print {
            .receipt {
                page-break-after: always;
                margin-bottom: 0;
            }
            .receipt:last-child {
                page-break-after: auto;
            }
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }
        
        .receipt {
            max-width: 400px;
            margin: 0 auto 40px auto;
            background: white;
            padding: 30px;
            border: 2px solid #000;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .receipt-header {
            text-align: center;
            border-bottom: 2px dashed #000;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }
        
        .store-name {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .store-tagline {
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }
        
        .receipt-info {
            margin-bottom: 20px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 13px;
        }
        
        .info-label {
            font-weight: bold;
            width: 40%;
        }
        
        .info-value {
            width: 60%;
            text-align: right;
        }
        
        .divider {
            border-top: 1px dashed #000;
            margin: 15px 0;
        }
        
        .items-section {
            margin: 20px 0;
        }
        
        .items-header {
            font-weight: bold;
            border-bottom: 1px solid #000;
            padding-bottom: 5px;
            margin-bottom: 10px;
            font-size: 14px;
        }
        
        .item-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 13px;
            padding: 5px 0;
        }
        
        .item-name {
            flex: 1;
            margin-right: 10px;
        }
        
        .item-quantity {
            font-weight: bold;
            margin-right: 10px;
            min-width: 30px;
        }
        
        .item-price {
            text-align: right;
            min-width: 80px;
        }
        
        .totals-section {
            margin-top: 20px;
            border-top: 2px dashed #000;
            padding-top: 15px;
        }
        
        .total-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .total-label {
            font-weight: bold;
        }
        
        .grand-total {
            font-size: 18px;
            font-weight: bold;
            border-top: 2px solid #000;
            padding-top: 10px;
            margin-top: 10px;
        }
        
        .payment-info {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px dashed #000;
            font-size: 12px;
        }
        
        .payment-status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
        }
        
        .status-paid {
            background: #27ae60;
            color: white;
        }
        
        .status-pending {
            background: #f39c12;
            color: white;
        }
        
        .status-failed {
            background: #e74c3c;
            color: white;
        }
        
        .order-status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
            margin-left: 10px;
        }
        
        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 15px;
            border-top: 1px dashed #000;
            font-size: 11px;
            color: #666;
        }
        
        .thank-you {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
            font-weight: bold;
            font-style: italic;
        }
    </style>
</head>
<body>
    ${orders.map(order => {
        const date = new Date(order.createdAt);
        const dateStr = date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
        const timeStr = date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        const paymentStatus = order.payment?.status || 'pending';
        const statusClass = paymentStatus === 'paid' ? 'status-paid' : paymentStatus === 'failed' ? 'status-failed' : 'status-pending';
        
        return `
    <div class="receipt">
        <div class="receipt-header">
            <div class="store-name">NANA BAAKO STORES</div>
            <div class="store-tagline">Quality Products, Great Service</div>
        </div>
        
        <div class="receipt-info">
            <div class="info-row">
                <span class="info-label">Order Number:</span>
                <span class="info-value">${order.orderNumber || 'N/A'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Date:</span>
                <span class="info-value">${dateStr}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Time:</span>
                <span class="info-value">${timeStr}</span>
            </div>
            <div class="divider"></div>
            <div class="info-row">
                <span class="info-label">Customer:</span>
                <span class="info-value">${order.customer?.name || 'N/A'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Phone:</span>
                <span class="info-value">${order.customer?.phone || 'N/A'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Email:</span>
                <span class="info-value">${order.customer?.email || 'N/A'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Location:</span>
                <span class="info-value">${order.customer?.location || 'N/A'}</span>
            </div>
        </div>
        
        <div class="items-section">
            <div class="items-header">ITEMS</div>
            ${order.items.map(item => `
            <div class="item-row">
                <span class="item-name">${item.name}</span>
                <span class="item-quantity">x${item.quantity}</span>
                <span class="item-price">GH₵${(item.price * item.quantity).toFixed(2)}</span>
            </div>
            `).join('')}
        </div>
        
        <div class="totals-section">
            <div class="total-row">
                <span class="total-label">Subtotal:</span>
                <span>GH₵${Number(order.subtotal || 0).toFixed(2)}</span>
            </div>
            <div class="total-row">
                <span class="total-label">Service Fee:</span>
                <span>GH₵${Number(order.fee || 0).toFixed(2)}</span>
            </div>
            <div class="total-row grand-total">
                <span>TOTAL:</span>
                <span>GH₵${Number(order.total || 0).toFixed(2)}</span>
            </div>
        </div>
        
        <div class="payment-info">
            <div class="info-row">
                <span class="info-label">Payment Status:</span>
                <span class="info-value">
                    <span class="payment-status ${statusClass}">${paymentStatus}</span>
                </span>
            </div>
            ${order.payment?.reference ? `
            <div class="info-row">
                <span class="info-label">Payment Ref:</span>
                <span class="info-value" style="font-size: 10px;">${order.payment.reference}</span>
            </div>
            ` : ''}
            <div class="info-row">
                <span class="info-label">Order Status:</span>
                <span class="info-value">
                    <span class="order-status" style="background: #3498db; color: white;">${order.status || 'new'}</span>
                </span>
            </div>
        </div>
        
        <div class="thank-you">
            Thank you for your order!
        </div>
        
        <div class="footer">
            <div>For inquiries, contact us</div>
            <div style="margin-top: 5px;">${order.customer?.phone || ''}</div>
        </div>
    </div>
        `;
    }).join('')}
</body>
</html>`;
        
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="orders-receipts-${new Date().toISOString().split('T')[0]}.html"`);
        res.send(receiptHTML);
    } catch (error) {
        console.error('Error downloading orders:', error);
        res.status(500).json({ message: 'Failed to download orders', error: error.message });
    }
});

// Admin: sales totals - Only counts PAID orders
app.get('/api/admin/sales', requireAdmin, async(req, res) => {
    try {
        const { period } = req.query; // day | month | year
        const now = new Date();
        let start;
        
        if (period === 'day') {
            start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        } else if (period === 'month') {
            start = new Date(now.getFullYear(), now.getMonth(), 1);
        } else if (period === 'year') {
            start = new Date(now.getFullYear(), 0, 1);
        } else {
            return res.status(400).json({ message: 'Invalid period' });
        }

        // Only count orders with payment status = 'paid'
        const paidMatch = { 
            createdAt: { $gte: start }, 
            'payment.status': 'paid' 
        };
        
        const results = await Order.aggregate([
            { $match: paidMatch },
            { 
                $group: { 
                    _id: null, 
                    total: { $sum: '$total' },
                    subtotal: { $sum: '$subtotal' },
                    fees: { $sum: '$fee' },
                    count: { $sum: 1 } 
                } 
            }
        ]);
        
        const total = results[0]?.total || 0;
        const subtotal = results[0]?.subtotal || 0;
        const fees = results[0]?.fees || 0;
        const count = results[0]?.count || 0;
        
        res.json({ 
            period, 
            total: parseFloat(total.toFixed(2)), 
            subtotal: parseFloat(subtotal.toFixed(2)),
            fees: parseFloat(fees.toFixed(2)),
            count 
        });
    } catch (error) {
        console.error('Error computing sales:', error);
        res.status(500).json({ message: 'Failed to compute sales' });
    }
});

// Get products by category
app.get('/api/products/category/:category', async(req, res) => {
    try {
        const { category } = req.params;
        // Only show products with stock > 0
        const products = await Product.find({ category, stock: { $gt: 0 } }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('Error fetching products by category:', error);
        res.status(500).json({ message: 'Failed to fetch products by category' });
    }
});

// Get a single product
app.get('/api/products/:id', async(req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        // Only return if product has stock (for public access)
        if (product.stock <= 0) {
            return res.status(404).json({ message: 'Product out of stock' });
        }
        res.json(product);
    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ message: 'Failed to fetch product' });
    }
});

// Admin: Get all products (including out of stock)
app.get('/api/admin/products', requireAdmin, async(req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: 'Failed to fetch products' });
    }
});

// Create a new product
app.post('/api/products', requireAdmin, upload.single('image'), async(req, res) => {
    try {
        const { name, price, oldPrice, category, description, stock, sizes } = req.body;

        // Validate required fields
        if (!name || !price || !category) {
            return res.status(400).json({ message: 'Name, price, and category are required' });
        }

        // Validate stock (must be a number >= 0)
        const stockQuantity = parseInt(stock) || 0;
        if (stockQuantity < 0) {
            return res.status(400).json({ message: 'Stock quantity cannot be negative' });
        }

        // Default image URL in case no image is uploaded
        let imageUrl = `https://res.cloudinary.com/${process.env.CLOUDINARY_CLOUD_NAME}/image/upload/v1/product-images/default-product.jpg`;
        let publicId = null;

        // If file was uploaded, use its URL
        if (req.file) {
            imageUrl = req.file.path;
            publicId = req.file.filename;
        }

        const parsedSizesCreate = parseSizesField(sizes);
        console.log('Create product sizes raw:', sizes, 'parsed:', parsedSizesCreate);
        const newProduct = new Product({
            name,
            price: parseFloat(price),
            oldPrice: oldPrice !== undefined && oldPrice !== null && String(oldPrice).trim() !== '' ? parseFloat(oldPrice) : undefined,
            category,
            description: description || '',
            stock: stockQuantity,
            imageUrl,
            publicId,
            sizes: parsedSizesCreate
        });

        const savedProduct = await newProduct.save();
        res.status(201).json(savedProduct);
    } catch (error) {
        console.error('Error creating product:', error);

        // Handle Cloudinary specific errors
        if (error.message && error.message.includes('Must supply api_key')) {
            return res.status(500).json({
                message: 'Image upload configuration error. Please check server settings.'
            });
        }

        res.status(500).json({ message: 'Failed to create product: ' + error.message });
    }
});

// Update a product
app.put('/api/products/:id', requireAdmin, upload.single('image'), async(req, res) => {
    try {
        const { name, price, oldPrice, category, description, stock } = req.body;
        const product = await Product.findById(req.params.id);

        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Validate stock (must be a number >= 0)
        const stockQuantity = parseInt(stock);
        if (stockQuantity !== undefined && stockQuantity < 0) {
            return res.status(400).json({ message: 'Stock quantity cannot be negative' });
        }

        const updateData = {
            name,
            price: parseFloat(price),
            category,
            description: description || ''
        };
        if (typeof oldPrice !== 'undefined') {
            const parsedOld = String(oldPrice).trim() === '' ? undefined : parseFloat(oldPrice);
            updateData.oldPrice = isNaN(parsedOld) ? undefined : parsedOld;
        }
        // Parse sizes if provided; only update when there are valid values
        if (typeof req.body.sizes !== 'undefined') {
            const parsedSizesUpdate = parseSizesField(req.body.sizes);
            console.log('Update product sizes raw:', req.body.sizes, 'parsed:', parsedSizesUpdate);
            if (Array.isArray(parsedSizesUpdate) && parsedSizesUpdate.length > 0) {
                updateData.sizes = parsedSizesUpdate;
            }
            // If empty/invalid, do NOT touch existing sizes to avoid wiping them
        }

        // Only update stock if provided
        if (stockQuantity !== undefined) {
            updateData.stock = stockQuantity;
        }

        // Only update image if a new one is uploaded
        if (req.file) {
            updateData.imageUrl = req.file.path;
            updateData.publicId = req.file.filename;

            // Delete old image from Cloudinary if it exists and is not the default
            if (product.publicId) {
                try {
                    await cloudinary.uploader.destroy(product.publicId);
                } catch (deleteError) {
                    console.error('Error deleting old image:', deleteError);
                }
            }
        }

        const updatedProduct = await Product.findByIdAndUpdate(
            req.params.id,
            updateData, { new: true }
        );

        res.json(updatedProduct);
    } catch (error) {
        console.error('Error updating product:', error);

        // Handle Cloudinary specific errors
        if (error.message && error.message.includes('Must supply api_key')) {
            return res.status(500).json({
                message: 'Image upload configuration error. Please check server settings.'
            });
        }

        res.status(500).json({ message: 'Failed to update product: ' + error.message });
    }
});

// Delete a product
app.delete('/api/products/:id', requireAdmin, async(req, res) => {
    try {
        const product = await Product.findById(req.params.id);

        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Delete product image from Cloudinary if it exists and is not the default
        if (product.publicId) {
            try {
                await cloudinary.uploader.destroy(product.publicId);
            } catch (deleteError) {
                console.error('Error deleting image from Cloudinary:', deleteError);
            }
        }

        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({ message: 'Failed to delete product' });
    }
});

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Handle 404
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);

    // Handle multer errors
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large. Maximum size is 5MB.' });
        }
    }

    // Handle Cloudinary errors
    if (err.message && err.message.includes('Must supply api_key')) {
        return res.status(500).json({
            message: 'Image upload service configuration error. Please contact administrator.'
        });
    }

    res.status(500).json({ message: err.message || 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin`);
    console.log(`Website: http://localhost:${PORT}`);
});
