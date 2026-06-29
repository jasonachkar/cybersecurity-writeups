# Mitigating API Vulnerabilities in Node.js (Express)

Node.js, specifically the Express framework, is highly flexible, but out of the box, it lacks many default security constraints. You must explicitly configure middleware to defend against the OWASP API Security Top 10.

---

## 1. Preventing BOLA / IDOR (API1:2023)

In Node.js applications, especially those using MongoDB/Mongoose or Prisma, you must scope queries to the authenticated user.

**Insecure:**
```javascript
app.get('/api/invoices/:id', async (req, res) => {
    // VULNERABLE: Retrieves the invoice based solely on the URL parameter
    const invoice = await Invoice.findById(req.params.id);
    res.json(invoice);
});
```

**Secure:**
```javascript
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
    // SECURE: Enforces that the invoice must belong to the logged-in user
    const invoice = await Invoice.findOne({ 
        _id: req.params.id, 
        userId: req.user.id // Extracted from JWT middleware
    });
    
    if (!invoice) return res.status(404).send('Not Found');
    res.json(invoice);
});
```

## 2. Preventing Mass Assignment (API3:2023)

Express parses JSON payloads directly into `req.body`. If you pass `req.body` directly to a database insert/update function, an attacker can modify fields they shouldn't.

**Use Destructuring or Validation Libraries:**
```javascript
// Using Joi or Zod for strict validation is highly recommended
app.put('/api/users/profile', authenticateToken, async (req, res) => {
    // SECURE: Explicitly extract only the allowed fields
    const { firstName, lastName, bio } = req.body;
    
    // The "isAdmin" flag sent by an attacker in req.body is ignored
    await User.findByIdAndUpdate(req.user.id, {
        firstName,
        lastName,
        bio
    });
    
    res.status(200).send('Profile updated');
});
```

## 3. Rate Limiting (API4:2023)

Use the `express-rate-limit` package to prevent brute-force attacks and DoS.

```javascript
const rateLimit = require('express-rate-limit');

// Basic rate limiting middleware
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window`
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply to all /api routes
app.use('/api/', apiLimiter);
```

## 4. Preventing Security Misconfigurations (API8:2023)

### HTTP Headers with Helmet
By default, Express exposes an `X-Powered-By: Express` header and lacks security headers like HSTS or XSS protections. Use `helmet`.
```javascript
const helmet = require('helmet');
// Automatically sets 15+ secure HTTP headers
app.use(helmet()); 
```

### Strict CORS Setup
Use the `cors` middleware, but never configure it dynamically to reflect the requester's origin blindly.
```javascript
const cors = require('cors');

const corsOptions = {
    origin: 'https://my-trusted-frontend.com',
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
```
