# OWASP API Security - Code Examples & Mitigations

Practical implementation patterns and secure code examples for mitigating the OWASP API Security Top 10 risks.

## Table of Contents

1. [Authorization Middleware Patterns](#authorization-middleware-patterns)
2. [Authentication Best Practices](#authentication-best-practices)
3. [Input Validation Schemas](#input-validation-schemas)
4. [Rate Limiting Implementations](#rate-limiting-implementations)
5. [Secure API Response Patterns](#secure-api-response-patterns)
6. [SSRF Prevention Utilities](#ssrf-prevention-utilities)
7. [Security Headers Configuration](#security-headers-configuration)
8. [API Testing Scripts](#api-testing-scripts)

---

## Authorization Middleware Patterns

### Node.js/Express - Object Level Authorization

```javascript
// middleware/authorization.js

const db = require('../database');

/**
 * Object Level Authorization Middleware
 * Verifies user has access to the requested resource
 */
const objectAuthorization = (resourceType, paramName = 'id') => {
  return async (req, res, next) => {
    const resourceId = req.params[paramName];
    const userId = req.user.id;
    const tenantId = req.user.tenantId;

    try {
      // Fetch resource with ownership filter
      const resource = await db(resourceType)
        .where({ id: resourceId, tenant_id: tenantId })
        .first();

      if (!resource) {
        // Log potential attack
        logSecurityEvent({
          type: 'UNAUTHORIZED_OBJECT_ACCESS_ATTEMPT',
          userId,
          resourceType,
          resourceId,
          ip: req.ip
        });
        return res.status(404).json({ error: 'Resource not found' });
      }

      // Check ownership or permission
      const hasAccess = await checkResourceAccess(userId, resource, req.method);
      if (!hasAccess) {
        logSecurityEvent({
          type: 'PERMISSION_DENIED',
          userId,
          resourceType,
          resourceId,
          action: req.method
        });
        return res.status(403).json({ error: 'Access denied' });
      }

      // Attach resource to request for handler use
      req.resource = resource;
      next();
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
};

/**
 * Function Level Authorization Middleware
 * Verifies user has required role/permission
 */
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user?.role;

    if (!userRole || !allowedRoles.includes(userRole)) {
      logSecurityEvent({
        type: 'UNAUTHORIZED_FUNCTION_ACCESS',
        userId: req.user?.id,
        endpoint: req.originalUrl,
        method: req.method,
        userRole,
        requiredRoles: allowedRoles
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

/**
 * Property Level Authorization
 * Filters response based on user permissions
 */
const filterResponseProperties = (resource, userPermissions) => {
  const sensitiveFields = {
    user: ['passwordHash', 'ssn', 'creditScore', 'internalNotes'],
    order: ['internalCost', 'profitMargin', 'supplierInfo'],
    account: ['apiSecret', 'encryptionKey', 'auditLog']
  };

  const resourceType = resource.constructor.name.toLowerCase();
  const fieldsToRemove = sensitiveFields[resourceType] || [];

  const filtered = { ...resource };
  
  fieldsToRemove.forEach(field => {
    if (!userPermissions.includes(`read:${resourceType}:${field}`)) {
      delete filtered[field];
    }
  });

  return filtered;
};

module.exports = {
  objectAuthorization,
  requireRole,
  filterResponseProperties
};
```

### Usage Example

```javascript
// routes/orders.js
const express = require('express');
const router = express.Router();
const { objectAuthorization, requireRole } = require('../middleware/authorization');

// Regular user: can only access their own orders
router.get('/orders/:id',
  authenticate,
  objectAuthorization('orders'),
  (req, res) => {
    res.json(req.resource);
  }
);

// Admin only: can list all orders
router.get('/admin/orders',
  authenticate,
  requireRole('admin', 'superadmin'),
  async (req, res) => {
    const orders = await db('orders')
      .where({ tenant_id: req.user.tenantId })
      .limit(100);
    res.json(orders);
  }
);

// Delete: requires superadmin
router.delete('/orders/:id',
  authenticate,
  requireRole('superadmin'),
  objectAuthorization('orders'),
  async (req, res) => {
    await db('orders').where({ id: req.params.id }).delete();
    res.json({ status: 'deleted' });
  }
);
```

---

## Authentication Best Practices

### JWT Implementation with Refresh Tokens

```javascript
// auth/jwt.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

class AuthService {
  /**
   * Generate access token with minimal claims
   */
  generateAccessToken(user) {
    return jwt.sign(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenantId,
        type: 'access'
      },
      JWT_SECRET,
      {
        expiresIn: ACCESS_TOKEN_EXPIRY,
        algorithm: 'RS256', // Asymmetric for production
        issuer: 'api.example.com',
        audience: 'app.example.com'
      }
    );
  }

  /**
   * Generate refresh token (stored in DB)
   */
  async generateRefreshToken(userId) {
    const token = crypto.randomBytes(64).toString('hex');
    const hash = await bcrypt.hash(token, 10);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db('refresh_tokens').insert({
      user_id: userId,
      token_hash: hash,
      expires_at: expiresAt,
      created_at: new Date()
    });

    return token;
  }

  /**
   * Verify access token
   */
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ['RS256'], // Only allow expected algorithm
        issuer: 'api.example.com',
        audience: 'app.example.com'
      });

      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(refreshToken, userId) {
    // Find valid refresh token
    const tokens = await db('refresh_tokens')
      .where({ user_id: userId })
      .where('expires_at', '>', new Date());

    for (const storedToken of tokens) {
      const valid = await bcrypt.compare(refreshToken, storedToken.token_hash);
      if (valid) {
        const user = await db('users').where({ id: userId }).first();
        return this.generateAccessToken(user);
      }
    }

    throw new Error('Invalid refresh token');
  }

  /**
   * Revoke refresh token (logout)
   */
  async revokeRefreshToken(refreshToken, userId) {
    const tokens = await db('refresh_tokens')
      .where({ user_id: userId });

    for (const storedToken of tokens) {
      const valid = await bcrypt.compare(refreshToken, storedToken.token_hash);
      if (valid) {
        await db('refresh_tokens')
          .where({ id: storedToken.id })
          .delete();
        return true;
      }
    }

    return false;
  }

  /**
   * Revoke all refresh tokens (password change, compromise)
   */
  async revokeAllTokens(userId) {
    await db('refresh_tokens')
      .where({ user_id: userId })
      .delete();
  }
}

module.exports = new AuthService();
```

### Secure Login Endpoint

```javascript
// routes/auth.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts, please try again later' }
});

// Progressive slowdown
const loginSlowdown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 3, // Start slowing after 3 attempts
  delayMs: (hits) => hits * 500, // Add 500ms per attempt
  maxDelayMs: 5000
});

router.post('/login', loginLimiter, loginSlowdown, async (req, res) => {
  const { email, password } = req.body;
  
  // Generic error message
  const invalidCredentials = { error: 'Invalid email or password' };
  
  try {
    // Find user
    const user = await db('users')
      .where({ email: email.toLowerCase() })
      .first();

    if (!user) {
      // Prevent timing attacks - still compute bcrypt
      await bcrypt.compare(password, '$2b$10$invalidhashvalue1234567890');
      return res.status(401).json(invalidCredentials);
    }

    // Check if account is locked
    if (user.locked_until && user.locked_until > new Date()) {
      return res.status(423).json({
        error: 'Account locked',
        locked_until: user.locked_until
      });
    }

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    
    if (!valid) {
      // Increment failed attempts
      await incrementFailedAttempts(user.id);
      return res.status(401).json(invalidCredentials);
    }

    // Reset failed attempts on success
    await resetFailedAttempts(user.id);

    // Generate tokens
    const accessToken = authService.generateAccessToken(user);
    const refreshToken = await authService.generateRefreshToken(user.id);

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/api/auth/refresh'
    });

    // Log successful login
    logSecurityEvent({
      type: 'LOGIN_SUCCESS',
      userId: user.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      accessToken,
      expiresIn: 900 // 15 minutes in seconds
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});
```

---

## Input Validation Schemas

### JSON Schema Validation (Node.js with AJV)

```javascript
// validation/schemas.js
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const ajv = new Ajv({ allErrors: true, removeAdditional: 'all' });
addFormats(ajv);

// User creation schema
const createUserSchema = {
  type: 'object',
  properties: {
    email: {
      type: 'string',
      format: 'email',
      maxLength: 255
    },
    password: {
      type: 'string',
      minLength: 12,
      maxLength: 128,
      pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+'
    },
    name: {
      type: 'string',
      minLength: 1,
      maxLength: 100,
      pattern: '^[a-zA-Z\\s\\-\\.]+$'
    },
    phone: {
      type: 'string',
      pattern: '^\\+?[1-9]\\d{1,14}$'
    }
  },
  required: ['email', 'password', 'name'],
  additionalProperties: false // Prevents mass assignment
};

// Order creation schema
const createOrderSchema = {
  type: 'object',
  properties: {
    items: {
      type: 'array',
      minItems: 1,
      maxItems: 100,
      items: {
        type: 'object',
        properties: {
          productId: {
            type: 'string',
            pattern: '^[a-zA-Z0-9\\-]{1,50}$'
          },
          quantity: {
            type: 'integer',
            minimum: 1,
            maximum: 999
          }
        },
        required: ['productId', 'quantity'],
        additionalProperties: false
      }
    },
    shippingAddress: {
      type: 'object',
      properties: {
        street: { type: 'string', maxLength: 200 },
        city: { type: 'string', maxLength: 100 },
        state: { type: 'string', maxLength: 50 },
        zipCode: { type: 'string', pattern: '^[A-Z0-9\\-\\s]{3,10}$' },
        country: { type: 'string', minLength: 2, maxLength: 2 }
      },
      required: ['street', 'city', 'zipCode', 'country'],
      additionalProperties: false
    },
    notes: {
      type: 'string',
      maxLength: 1000
    }
  },
  required: ['items', 'shippingAddress'],
  additionalProperties: false
};

// Pagination schema
const paginationSchema = {
  type: 'object',
  properties: {
    page: {
      type: 'integer',
      minimum: 1,
      maximum: 10000,
      default: 1
    },
    limit: {
      type: 'integer',
      minimum: 1,
      maximum: 100,
      default: 20
    },
    sortBy: {
      type: 'string',
      enum: ['created_at', 'updated_at', 'name', 'price']
    },
    sortOrder: {
      type: 'string',
      enum: ['asc', 'desc'],
      default: 'desc'
    }
  },
  additionalProperties: false
};

// Compile schemas
const validators = {
  createUser: ajv.compile(createUserSchema),
  createOrder: ajv.compile(createOrderSchema),
  pagination: ajv.compile(paginationSchema)
};

// Validation middleware factory
const validate = (schemaName) => {
  return (req, res, next) => {
    const validator = validators[schemaName];
    const data = req.method === 'GET' ? req.query : req.body;

    if (!validator(data)) {
      return res.status(400).json({
        error: 'Validation failed',
        details: validator.errors.map(e => ({
          field: e.instancePath || e.params.missingProperty,
          message: e.message
        }))
      });
    }

    // Sanitized data (additionalProperties removed)
    if (req.method === 'GET') {
      req.query = data;
    } else {
      req.body = data;
    }

    next();
  };
};

module.exports = { validate, validators };
```

---

## Rate Limiting Implementations

### Redis-Based Distributed Rate Limiting

```javascript
// middleware/rateLimiter.js
const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URL);

/**
 * Sliding Window Rate Limiter
 */
class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000; // 1 minute default
    this.max = options.max || 100;
    this.keyPrefix = options.keyPrefix || 'rl:';
    this.keyGenerator = options.keyGenerator || ((req) => req.ip);
    this.skipFailedRequests = options.skipFailedRequests || false;
    this.skipSuccessfulRequests = options.skipSuccessfulRequests || false;
  }

  async isRateLimited(key) {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Using Redis sorted set for sliding window
    const fullKey = `${this.keyPrefix}${key}`;

    const pipeline = redis.pipeline();
    
    // Remove old entries
    pipeline.zremrangebyscore(fullKey, 0, windowStart);
    
    // Count current window
    pipeline.zcard(fullKey);
    
    // Add current request
    pipeline.zadd(fullKey, now, `${now}-${Math.random()}`);
    
    // Set expiry
    pipeline.expire(fullKey, Math.ceil(this.windowMs / 1000));

    const results = await pipeline.exec();
    const count = results[1][1];

    return {
      limited: count >= this.max,
      current: count,
      limit: this.max,
      remaining: Math.max(0, this.max - count - 1),
      resetTime: new Date(now + this.windowMs)
    };
  }

  middleware() {
    return async (req, res, next) => {
      const key = this.keyGenerator(req);
      const result = await this.isRateLimited(key);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', result.limit);
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset', result.resetTime.toISOString());

      if (result.limited) {
        res.setHeader('Retry-After', Math.ceil(this.windowMs / 1000));
        return res.status(429).json({
          error: 'Too many requests',
          retryAfter: Math.ceil(this.windowMs / 1000)
        });
      }

      next();
    };
  }
}

// Preset configurations
const rateLimiters = {
  // General API rate limit
  api: new RateLimiter({
    windowMs: 60000,
    max: 100,
    keyGenerator: (req) => req.user?.id || req.ip
  }),

  // Strict limit for authentication
  auth: new RateLimiter({
    windowMs: 15 * 60000, // 15 minutes
    max: 5,
    keyGenerator: (req) => `auth:${req.ip}`
  }),

  // Password reset (very strict)
  passwordReset: new RateLimiter({
    windowMs: 60 * 60000, // 1 hour
    max: 3,
    keyGenerator: (req) => `pwreset:${req.body?.email || req.ip}`
  }),

  // Expensive operations
  expensive: new RateLimiter({
    windowMs: 60000,
    max: 10,
    keyGenerator: (req) => `expensive:${req.user?.id || req.ip}`
  })
};

module.exports = rateLimiters;
```

---

## Secure API Response Patterns

### Response Serialization with Field Filtering

```javascript
// serializers/response.js

/**
 * Base serializer with field filtering
 */
class Serializer {
  constructor(fields, options = {}) {
    this.publicFields = fields.public || [];
    this.adminFields = fields.admin || [];
    this.ownerFields = fields.owner || [];
    this.sensitiveFields = fields.sensitive || [];
    this.transforms = options.transforms || {};
  }

  serialize(data, context = {}) {
    if (Array.isArray(data)) {
      return data.map(item => this.serializeOne(item, context));
    }
    return this.serializeOne(data, context);
  }

  serializeOne(item, context) {
    const { user, isOwner, includeFields = [] } = context;
    let allowedFields = [...this.publicFields];

    // Add admin fields if user is admin
    if (user?.role === 'admin' || user?.role === 'superadmin') {
      allowedFields = [...allowedFields, ...this.adminFields];
    }

    // Add owner fields if user owns the resource
    if (isOwner) {
      allowedFields = [...allowedFields, ...this.ownerFields];
    }

    // Add explicitly requested fields (if permitted)
    includeFields.forEach(field => {
      if (!this.sensitiveFields.includes(field)) {
        allowedFields.push(field);
      }
    });

    // Build response object
    const result = {};
    allowedFields.forEach(field => {
      if (item[field] !== undefined) {
        // Apply transform if defined
        if (this.transforms[field]) {
          result[field] = this.transforms[field](item[field], item);
        } else {
          result[field] = item[field];
        }
      }
    });

    return result;
  }
}

// User serializer
const userSerializer = new Serializer({
  public: ['id', 'name', 'avatar', 'created_at'],
  owner: ['email', 'phone', 'preferences', 'notification_settings'],
  admin: ['role', 'status', 'last_login', 'login_count'],
  sensitive: ['password_hash', 'ssn', 'credit_score', 'api_key']
}, {
  transforms: {
    phone: (phone) => phone ? phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2') : null,
    email: (email) => email.toLowerCase()
  }
});

// Order serializer
const orderSerializer = new Serializer({
  public: ['id', 'status', 'created_at', 'item_count'],
  owner: ['items', 'total', 'shipping_address', 'tracking_number'],
  admin: ['internal_notes', 'cost_breakdown', 'profit_margin'],
  sensitive: ['supplier_cost', 'api_response']
});

module.exports = {
  Serializer,
  userSerializer,
  orderSerializer
};
```

---

## SSRF Prevention Utilities

### URL Validation and Safe Fetching

```javascript
// utils/safeFetch.js
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');
const fetch = require('node-fetch');

class SafeFetcher {
  constructor(options = {}) {
    this.allowedSchemes = options.allowedSchemes || ['https'];
    this.blockedPorts = options.blockedPorts || [22, 23, 25, 3389, 6379, 27017];
    this.maxRedirects = options.maxRedirects || 0;
    this.timeout = options.timeout || 5000;
    this.maxResponseSize = options.maxResponseSize || 10 * 1024 * 1024; // 10MB
    
    // IP ranges to block
    this.blockedRanges = [
      '0.0.0.0/8',
      '10.0.0.0/8',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '172.16.0.0/12',
      '192.168.0.0/16',
      '224.0.0.0/4',
      '::1/128',
      'fc00::/7',
      'fe80::/10'
    ].map(cidr => {
      const [addr, bits] = cidr.split('/');
      return { addr: ipaddr.parse(addr), bits: parseInt(bits) };
    });
  }

  /**
   * Validate URL before fetching
   */
  async validateUrl(urlString) {
    let url;
    try {
      url = new URL(urlString);
    } catch {
      throw new Error('Invalid URL format');
    }

    // Check scheme
    if (!this.allowedSchemes.includes(url.protocol.replace(':', ''))) {
      throw new Error(`Scheme not allowed: ${url.protocol}`);
    }

    // Check port
    const port = url.port || (url.protocol === 'https:' ? 443 : 80);
    if (this.blockedPorts.includes(parseInt(port))) {
      throw new Error(`Port not allowed: ${port}`);
    }

    // Resolve DNS and check IP
    const hostname = url.hostname;
    let addresses;
    try {
      addresses = await dns.resolve4(hostname);
    } catch {
      try {
        addresses = await dns.resolve6(hostname);
      } catch {
        throw new Error(`Cannot resolve hostname: ${hostname}`);
      }
    }

    // Check each resolved IP
    for (const addr of addresses) {
      const ip = ipaddr.parse(addr);
      for (const range of this.blockedRanges) {
        if (ip.kind() === range.addr.kind() && ip.match(range.addr, range.bits)) {
          throw new Error(`IP address not allowed: ${addr}`);
        }
      }
    }

    return { url, resolvedIPs: addresses };
  }

  /**
   * Safely fetch a URL
   */
  async fetch(urlString, options = {}) {
    // Validate URL
    const { url } = await this.validateUrl(urlString);

    // Fetch with safety options
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url.href, {
        ...options,
        signal: controller.signal,
        redirect: this.maxRedirects === 0 ? 'error' : 'follow',
        follow: this.maxRedirects,
        headers: {
          ...options.headers,
          'User-Agent': 'SafeFetcher/1.0'
        }
      });

      // Check response size
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > this.maxResponseSize) {
        throw new Error('Response too large');
      }

      // If redirect, validate new URL
      if (response.redirected) {
        await this.validateUrl(response.url);
      }

      return response;

    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Fetch and return text with size limit
   */
  async fetchText(urlString, options = {}) {
    const response = await this.fetch(urlString, options);
    
    // Read with size limit
    let text = '';
    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      text += decoder.decode(value, { stream: true });
      if (text.length > this.maxResponseSize) {
        reader.cancel();
        throw new Error('Response too large');
      }
    }

    return text;
  }
}

module.exports = new SafeFetcher();
```

---

## Security Headers Configuration

### Express Security Headers Middleware

```javascript
// middleware/securityHeaders.js

const securityHeaders = (options = {}) => {
  const defaults = {
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    },
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: {
      camera: [],
      microphone: [],
      geolocation: [],
      payment: []
    }
  };

  const config = { ...defaults, ...options };

  return (req, res, next) => {
    // Remove potentially dangerous headers
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');

    // Strict Transport Security (HTTPS only)
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      const hsts = config.hsts;
      let hstsValue = `max-age=${hsts.maxAge}`;
      if (hsts.includeSubDomains) hstsValue += '; includeSubDomains';
      if (hsts.preload) hstsValue += '; preload';
      res.setHeader('Strict-Transport-Security', hstsValue);
    }

    // Content Security Policy
    const csp = config.contentSecurityPolicy;
    const cspValue = Object.entries(csp)
      .map(([key, values]) => {
        const directive = key.replace(/([A-Z])/g, '-$1').toLowerCase();
        return `${directive} ${values.join(' ')}`;
      })
      .join('; ');
    res.setHeader('Content-Security-Policy', cspValue);

    // Other security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', config.referrerPolicy);
    
    // Permissions Policy
    const pp = config.permissionsPolicy;
    const ppValue = Object.entries(pp)
      .map(([feature, allowList]) => {
        const allow = allowList.length > 0 ? allowList.join(' ') : '';
        return `${feature}=(${allow})`;
      })
      .join(', ');
    res.setHeader('Permissions-Policy', ppValue);

    // Cache control for API responses
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
    }

    next();
  };
};

module.exports = securityHeaders;
```

---

## API Testing Scripts

### BOLA Testing Script

```bash
#!/bin/bash
# test_bola.sh - Test for Broken Object Level Authorization

BASE_URL="${1:-http://localhost:3000}"
USER_A_TOKEN="${2}"  # Token for user A
USER_B_ID="${3}"     # ID of user B's resource to try to access

echo "=== BOLA Testing Script ==="
echo "Testing: $BASE_URL"
echo ""

# Test endpoints for BOLA
ENDPOINTS=(
  "GET /api/users/{id}"
  "GET /api/users/{id}/orders"
  "GET /api/orders/{id}"
  "PUT /api/users/{id}"
  "DELETE /api/orders/{id}"
)

for endpoint in "${ENDPOINTS[@]}"; do
  METHOD=$(echo $endpoint | cut -d' ' -f1)
  PATH=$(echo $endpoint | cut -d' ' -f2 | sed "s/{id}/$USER_B_ID/g")
  
  echo "Testing: $METHOD $PATH"
  
  RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X "$METHOD" \
    -H "Authorization: Bearer $USER_A_TOKEN" \
    -H "Content-Type: application/json" \
    "$BASE_URL$PATH")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | sed '$d')
  
  if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "204" ]]; then
    echo "  ⚠️  POTENTIAL BOLA: Got $HTTP_CODE for other user's resource!"
    echo "  Response: $BODY"
  elif [[ "$HTTP_CODE" == "403" ]] || [[ "$HTTP_CODE" == "404" ]]; then
    echo "  ✅ SECURE: Got $HTTP_CODE (access denied)"
  else
    echo "  ❓ UNEXPECTED: Got $HTTP_CODE"
    echo "  Response: $BODY"
  fi
  echo ""
done
```

### API Security Audit Script

```python
#!/usr/bin/env python3
# api_security_audit.py - Comprehensive API security testing

import requests
import json
import sys
from urllib.parse import urljoin

class APISecurityAuditor:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token
        self.results = []
        
    def request(self, method, path, **kwargs):
        url = urljoin(self.base_url, path)
        headers = kwargs.pop('headers', {})
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        headers['Content-Type'] = 'application/json'
        
        try:
            response = requests.request(method, url, headers=headers, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            return None
    
    def test_authentication(self):
        """Test authentication vulnerabilities"""
        print("\n=== Testing Authentication ===")
        
        # Test missing authentication
        response = requests.get(urljoin(self.base_url, '/api/users/me'), timeout=10)
        if response.status_code == 200:
            self.results.append({
                'category': 'Authentication',
                'test': 'Missing Auth Check',
                'status': 'FAIL',
                'details': 'Endpoint accessible without authentication'
            })
            print("❌ /api/users/me accessible without auth")
        else:
            print("✅ Authentication required for protected endpoints")
        
        # Test weak token
        response = requests.get(
            urljoin(self.base_url, '/api/users/me'),
            headers={'Authorization': 'Bearer invalid_token'},
            timeout=10
        )
        if response.status_code == 200:
            self.results.append({
                'category': 'Authentication',
                'test': 'Token Validation',
                'status': 'FAIL',
                'details': 'Invalid token accepted'
            })
            print("❌ Invalid token accepted")
        else:
            print("✅ Invalid tokens rejected")
    
    def test_rate_limiting(self, endpoint='/api/users/me'):
        """Test rate limiting"""
        print("\n=== Testing Rate Limiting ===")
        
        responses = []
        for i in range(120):  # Send 120 requests rapidly
            response = self.request('GET', endpoint)
            if response:
                responses.append(response.status_code)
        
        rate_limited = 429 in responses
        if not rate_limited:
            self.results.append({
                'category': 'Rate Limiting',
                'test': 'API Rate Limit',
                'status': 'FAIL',
                'details': f'No rate limiting detected after {len(responses)} requests'
            })
            print(f"❌ No rate limiting after {len(responses)} requests")
        else:
            limit_at = responses.index(429)
            print(f"✅ Rate limited after {limit_at} requests")
    
    def test_security_headers(self):
        """Test security headers"""
        print("\n=== Testing Security Headers ===")
        
        response = self.request('GET', '/api/health')
        if not response:
            print("⚠️  Could not connect to API")
            return
        
        headers_to_check = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'clickjacking protection',
            'Content-Security-Policy': 'CSP'
        }
        
        headers_not_to_have = ['X-Powered-By', 'Server']
        
        for header, description in headers_to_check.items():
            if header in response.headers:
                print(f"✅ {header} present")
            else:
                self.results.append({
                    'category': 'Security Headers',
                    'test': description,
                    'status': 'WARN',
                    'details': f'Missing {header} header'
                })
                print(f"⚠️  Missing {header}")
        
        for header in headers_not_to_have:
            if header in response.headers:
                self.results.append({
                    'category': 'Security Headers',
                    'test': 'Information Disclosure',
                    'status': 'WARN',
                    'details': f'{header} header exposes server info'
                })
                print(f"⚠️  {header} header present (info disclosure)")
    
    def test_verbose_errors(self):
        """Test for verbose error messages"""
        print("\n=== Testing Error Messages ===")
        
        # Test invalid input
        response = self.request('POST', '/api/users', 
            json={'email': 'not-an-email', 'password': '123'})
        
        if response and response.status_code >= 400:
            body = response.text.lower()
            dangerous_keywords = ['stack', 'trace', 'exception', 'error at', 
                                'line', 'sql', 'query', 'database']
            
            found_keywords = [k for k in dangerous_keywords if k in body]
            if found_keywords:
                self.results.append({
                    'category': 'Error Handling',
                    'test': 'Verbose Errors',
                    'status': 'FAIL',
                    'details': f'Error response contains sensitive info: {found_keywords}'
                })
                print(f"❌ Verbose error detected: {found_keywords}")
            else:
                print("✅ Error messages don't expose sensitive info")
    
    def generate_report(self):
        """Generate audit report"""
        print("\n" + "="*50)
        print("SECURITY AUDIT REPORT")
        print("="*50)
        
        if not self.results:
            print("\n✅ No security issues detected!")
            return
        
        by_category = {}
        for result in self.results:
            cat = result['category']
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(result)
        
        for category, issues in by_category.items():
            print(f"\n{category}:")
            for issue in issues:
                status = '❌' if issue['status'] == 'FAIL' else '⚠️'
                print(f"  {status} {issue['test']}: {issue['details']}")
        
        fail_count = len([r for r in self.results if r['status'] == 'FAIL'])
        warn_count = len([r for r in self.results if r['status'] == 'WARN'])
        print(f"\nSummary: {fail_count} failures, {warn_count} warnings")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python api_security_audit.py <base_url> [token]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    auditor = APISecurityAuditor(base_url, token)
    auditor.test_authentication()
    auditor.test_rate_limiting()
    auditor.test_security_headers()
    auditor.test_verbose_errors()
    auditor.generate_report()
```

---

## Quick Reference Card

### OWASP API Security Top 10 Summary

| # | Risk | One-Line Prevention |
|---|------|---------------------|
| API1 | BOLA | Verify user owns every object they access |
| API2 | Broken Auth | MFA, rate limits, secure token handling |
| API3 | Object Property | Filter response fields, block mass assignment |
| API4 | Resource | Rate limit, pagination, timeouts everywhere |
| API5 | BFLA | Check role/permission before every function |
| API6 | Business Flow | CAPTCHA, device fingerprinting, behavioral analysis |
| API7 | SSRF | Validate URLs, block internal IPs, no redirects |
| API8 | Misconfig | Security headers, no debug mode, least privilege |
| API9 | Inventory | Document all APIs, sunset old versions |
| API10 | Unsafe Consumption | Validate ALL third-party data like user input |
