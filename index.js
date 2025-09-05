require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// --- 1. CONFIGURATION & SETUP ---
const { PORT = 4000, DB_USER, DB_PASSWORD, DB_SERVER, DB_DATABASE, JWT_SECRET, SESSION_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, FRONTEND_URL, BACKEND_URL, NODE_ENV } = process.env;

const app = express();
let pool;

// --- 2. MIDDLEWARE ---
app.use(helmet());
app.use(cors({ origin: FRONTEND_URL, optionsSuccessStatus: 200 }));
app.use(express.json());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' }
}));
app.use(passport.initialize());
app.use(passport.session());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many requests from this IP, please try again after 15 minutes',
});

// --- 3. PASSPORT STRATEGY ---
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/api/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    try {
        const userResult = await pool.query('SELECT * FROM "Users" WHERE email = $1', [email]);
        if (userResult.rows[0]) {
            return done(null, userResult.rows[0]);
        } else {
            const dummyPasswordHash = await bcrypt.hash(Date.now().toString() + email, 10);
            const newUserResult = await pool.query('INSERT INTO "Users" (name, email, "passwordHash") VALUES ($1, $2, $3) RETURNING *', [name, email, dummyPasswordHash]);
            return done(null, newUserResult.rows[0]);
        }
    } catch (err) {
        return done(err, null);
    }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT id, name, email FROM "Users" WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

// --- 4. API ROUTES ---
const apiRouter = express.Router();

// Public Routes
apiRouter.get('/celebrities', async (req, res, next) => {
    try {
        const result = await pool.query('SELECT * FROM "Celebrities"');
        res.json(result.rows);
    } catch (err) { next(err); }
});

apiRouter.get('/categories', async (req, res, next) => {
    try {
        const result = await pool.query('SELECT * FROM "Categories"');
        res.json(result.rows);
    } catch (err) { next(err); }
});

apiRouter.get('/products', async (req, res, next) => {
    try {
        const result = await pool.query(`
            SELECT p.*, cat."subcategorySlug", cat."subcategoryName", cat."mainCategoryTitle",
            CASE WHEN cat."mainCategoryTitle" = 'Men''s Outfits' THEN 'men' WHEN cat."mainCategoryTitle" = 'Women''s Outfits' THEN 'women' WHEN cat."mainCategoryTitle" = 'Kids'' Outfits' THEN 'kids' WHEN cat."mainCategoryTitle" = 'Accessories' THEN 'accessories' ELSE LOWER(REPLACE(cat."mainCategoryTitle", ' ', '-')) END AS "mainCategorySlug",
            STRING_AGG(celeb.slug, ',') AS "celebritySlugs"
            FROM "Products" AS p
            LEFT JOIN "Categories" AS cat ON p."categoryId" = cat.id
            LEFT JOIN "Product_Celebrity_Map" AS pcm ON p.id = pcm."productId"
            LEFT JOIN "Celebrities" AS celeb ON pcm."celebrityId" = celeb.id
            GROUP BY p.id, cat."subcategorySlug", cat."subcategoryName", cat."mainCategoryTitle"`);
        res.json(result.rows);
    } catch (err) { next(err); }
});

apiRouter.get('/suggestions', async (req, res, next) => {
    const { query } = req.query;
    if (!query || query.length < 2) return res.json([]);
    try {
        const searchQuery = `%${query}%`;
        const queryText = `
            (SELECT name FROM "Products" WHERE name ILIKE $1 LIMIT 3)
            UNION
            (SELECT name FROM "OutfitCollections" WHERE name ILIKE $1 LIMIT 3)
            UNION
            (SELECT name FROM "Celebrities" WHERE name ILIKE $1 LIMIT 2)
        `;
        const result = await pool.query(queryText, [searchQuery]);
        const suggestions = result.rows.map(item => item.name);
        res.json(suggestions);
    } catch (err) {
        console.error('Suggestions API Error:', err);
        res.status(500).json([]);
    }
});

apiRouter.get('/search', async (req, res, next) => {
    const { query } = req.query;
    if (!query) return res.status(400).json({ message: 'Search query is required.' });
    try {
        let productsResult = [];
        if (/^SR\d+$/i.test(query)) {
            const outfitResult = await pool.query('SELECT id FROM "OutfitCollections" WHERE "outfitCode" = $1', [query.toUpperCase()]);
            const outfit = outfitResult.rows[0];
            if (outfit) {
                const productsInOutfit = await pool.query('SELECT p.* FROM "Products" p JOIN "Outfit_Product_Map" opm ON p.id = opm."productId" WHERE opm."outfitId" = $1', [outfit.id]);
                productsResult = productsInOutfit.rows;
            }
        }
        if (productsResult.length === 0) {
            const outfitResult = await pool.query('SELECT id FROM "OutfitCollections" WHERE name ILIKE $1', [`%${query}%`]);
            const outfit = outfitResult.rows[0];
            if (outfit) {
                const productsInOutfit = await pool.query('SELECT p.* FROM "Products" p JOIN "Outfit_Product_Map" opm ON p.id = opm."productId" WHERE opm."outfitId" = $1', [outfit.id]);
                productsResult = productsInOutfit.rows;
            }
        }
        if (productsResult.length === 0) {
            const searchResult = await pool.query('SELECT * FROM "Products" WHERE name ILIKE $1 OR brand ILIKE $1', [`%${query}%`]);
            productsResult = searchResult.rows;
        }
        res.json(productsResult);
    } catch (err) {
        next(err);
    }
});

apiRouter.get('/outfits/:outfitCode', async (req, res, next) => {
    try {
        const { outfitCode } = req.params;
        const outfitResult = await pool.query('SELECT * FROM "OutfitCollections" WHERE "outfitCode" = $1', [outfitCode]);
        const outfit = outfitResult.rows[0];
        if (!outfit) return res.status(404).json({ message: 'Outfit not found.' });
        const productsResult = await pool.query('SELECT p.* FROM "Products" p JOIN "Outfit_Product_Map" opm ON p.id = opm."productId" WHERE opm."outfitId" = $1', [outfit.id]);
        res.json({ ...outfit, products: productsResult.rows });
    } catch (err) {
        next(err);
    }
});

// Auth Routes (with rate limiting)
apiRouter.post('/register', authLimiter, async (req, res, next) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required.' });
    }
    try {
        const userCheck = await pool.query('SELECT id FROM "Users" WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO "Users" (name, email, "passwordHash") VALUES ($1, $2, $3) RETURNING id, name, email',
            [name, email, passwordHash]
        );
        const newUser = result.rows[0];
        const token = jwt.sign({ id: newUser.id, email: newUser.email, name: newUser.name }, JWT_SECRET, { expiresIn: '1d' });
        res.status(201).json({ token, user: newUser });
    } catch (err) {
        next(err);
    }
});

apiRouter.post('/login', authLimiter, async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
    try {
        const result = await pool.query('SELECT * FROM "Users" WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        next(err);
    }
});

apiRouter.post('/forgot-password', authLimiter, async (req, res, next) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required.' });
    try {
        const userResult = await pool.query('SELECT id FROM "Users" WHERE email = $1', [email]);
        if (userResult.rows.length > 0) {
            const resetToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
            const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
            console.log(`Password reset link for ${email}: ${resetUrl}`);
        }
        res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    } catch (err) {
        next(err);
    }
});

// --- 5. REGISTER ROUTES ---
app.get('/', (req, res) => res.send('SRSTYLIEDEALS API is running.'));
app.get('/healthz', (req, res) => res.status(200).send('OK'));

// Google Auth routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login-failed`, session: false }), (req, res) => {
    const user = { id: req.user.id, name: req.user.name, email: req.user.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1d' });
    res.redirect(`${FRONTEND_URL}/auth/success?token=${token}&user=${encodeURIComponent(JSON.stringify(user))}`);
});

// Connect the main API router
app.use('/api', apiRouter);

// --- 6. ERROR HANDLING & SERVER START ---
app.use((err, req, res, next) => {
    console.error('❌ An unexpected error occurred:', err);
    res.status(500).json({ message: 'An internal server error occurred.' });
});

const startServer = async () => {
    try {
        const dbConfig = { user: DB_USER, password: DB_PASSWORD, host: DB_SERVER, database: DB_DATABASE, ssl: { rejectUnauthorized: false } };
        pool = new Pool(dbConfig);
        await pool.query('SELECT NOW()');
        console.log('✅ Connected to PostgreSQL successfully.');
        app.listen(PORT, () => console.log(`🚀 Server is listening on port ${PORT}`));
    } catch (err) {
        console.error('❌ Failed to start server or connect to database:', err);
        process.exit(1);
    }
};

startServer();

