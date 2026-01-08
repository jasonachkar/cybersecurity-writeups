# OWASP API Security Top 10 (2023)

A comprehensive guide to understanding and mitigating the most critical API security risks as defined by the Open Web Application Security Project.

## Table of Contents

1. [Introduction](#introduction)
2. [API1:2023 - Broken Object Level Authorization](#api12023---broken-object-level-authorization)
3. [API2:2023 - Broken Authentication](#api22023---broken-authentication)
4. [API3:2023 - Broken Object Property Level Authorization](#api32023---broken-object-property-level-authorization)
5. [API4:2023 - Unrestricted Resource Consumption](#api42023---unrestricted-resource-consumption)
6. [API5:2023 - Broken Function Level Authorization](#api52023---broken-function-level-authorization)
7. [API6:2023 - Unrestricted Access to Sensitive Business Flows](#api62023---unrestricted-access-to-sensitive-business-flows)
8. [API7:2023 - Server Side Request Forgery](#api72023---server-side-request-forgery)
9. [API8:2023 - Security Misconfiguration](#api82023---security-misconfiguration)
10. [API9:2023 - Improper Inventory Management](#api92023---improper-inventory-management)
11. [API10:2023 - Unsafe Consumption of APIs](#api102023---unsafe-consumption-of-apis)
12. [Changes from 2019 to 2023](#changes-from-2019-to-2023)
13. [API Security Testing Checklist](#api-security-testing-checklist)

---

## Introduction

### What is the OWASP API Security Top 10?

The OWASP API Security Top 10 is a list of the most critical security risks facing Application Programming Interfaces (APIs). First released in 2019 and updated in 2023, it provides guidance for developers, security professionals, and organizations to understand and mitigate API-specific vulnerabilities.

### Why API Security Matters

```
┌─────────────────────────────────────────────────────────────────────┐
│                     API Security Landscape                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  📊 Statistics (2024-2025)                                          │
│  ├─ 95% of organizations experienced an API security incident       │
│  ├─ 75%+ of API vulnerabilities relate to improper access control   │
│  ├─ 40% of API attacks involve BOLA (Broken Object Level Auth)      │
│  └─ APIs are the #1 attack vector for web applications              │
│                                                                      │
│  🎯 Why APIs Are Targeted                                           │
│  ├─ Direct access to sensitive data                                 │
│  ├─ Often less protected than web UI                                │
│  ├─ Machine-to-machine = easier automation                          │
│  ├─ Microservices increase attack surface                           │
│  └─ Mobile apps rely heavily on APIs                                │
│                                                                      │
│  💥 Impact of API Breaches                                          │
│  ├─ Mass data exfiltration                                          │
│  ├─ Account takeover at scale                                       │
│  ├─ Financial fraud                                                 │
│  ├─ Regulatory fines (GDPR, HIPAA, PCI-DSS)                        │
│  └─ Reputational damage                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2023 Top 10 Overview

| Rank | Risk | Description | Severity |
|------|------|-------------|----------|
| API1 | Broken Object Level Authorization | Access other users' data via ID manipulation | Critical |
| API2 | Broken Authentication | Exploit weak authentication mechanisms | Critical |
| API3 | Broken Object Property Level Authorization | Access/modify unauthorized object properties | High |
| API4 | Unrestricted Resource Consumption | Exhaust resources via unlimited requests | High |
| API5 | Broken Function Level Authorization | Access unauthorized admin/privileged functions | Critical |
| API6 | Unrestricted Access to Sensitive Business Flows | Abuse business logic via automation | High |
| API7 | Server Side Request Forgery | Make server request internal/external resources | High |
| API8 | Security Misconfiguration | Exploit misconfigurations in API stack | Medium-High |
| API9 | Improper Inventory Management | Target undocumented/deprecated API versions | Medium |
| API10 | Unsafe Consumption of APIs | Exploit trust in third-party APIs | Medium |

---

## API1:2023 - Broken Object Level Authorization

### Overview

Broken Object Level Authorization (BOLA), also known as Insecure Direct Object Reference (IDOR), is the #1 API security risk. It occurs when an API fails to verify that the requesting user has permission to access a specific object.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BOLA Attack Flow                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Attacker authenticates legitimately                             │
│     └─ GET /api/users/attacker-123/profile  ✓ Returns own data     │
│                                                                      │
│  2. Attacker modifies object ID                                     │
│     └─ GET /api/users/victim-456/profile    ← ID changed           │
│                                                                      │
│  3. API fails to validate ownership                                 │
│     └─ Server returns victim's data         ✗ BOLA Vulnerability   │
│                                                                      │
│  Impact: Data breach, privacy violation, account takeover           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Real-World Examples

**Uber (2019):** Security researcher discovered that changing the user phone number in an API request exposed access tokens, enabling account takeover of any Uber user, driver, or Uber Eats account.

**Peloton (2021):** Unauthenticated API requests with modified user IDs exposed personal data including age, gender, weight, and workout statistics of millions of users, including celebrities and political figures.

**John Deere (2021):** Security researchers found that modifying user IDs in API requests exposed customer names, addresses, equipment information, and purchase history.

### Vulnerable Code Example

```python
# ❌ VULNERABLE: No authorization check
@app.route('/api/orders/<order_id>', methods=['GET'])
@require_authentication
def get_order(order_id):
    # Only checks if user is authenticated, not if they own this order
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(order.to_dict())
```

```python
# ✅ SECURE: Object-level authorization check
@app.route('/api/orders/<order_id>', methods=['GET'])
@require_authentication
def get_order(order_id, current_user):
    # Fetch order WITH ownership filter
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.user_id == current_user.id  # Critical: ownership check
    ).first()
    
    if not order:
        # Return 404 regardless of reason (don't reveal existence)
        return jsonify({'error': 'Not found'}), 404
    
    return jsonify(order.to_dict())
```

### Prevention Strategies

| Strategy | Implementation |
|----------|----------------|
| **Object-Level Authorization** | Verify user owns/has access to every requested object |
| **Indirect References** | Use UUIDs instead of sequential IDs |
| **Authorization Middleware** | Centralize authorization checks |
| **Record-Level Security** | Implement RLS at database level |
| **Audit Logging** | Log all access attempts for detection |

### Testing Techniques

```bash
# Manual Testing: Parameter tampering
# 1. Capture legitimate request
GET /api/accounts/ACC-001/transactions HTTP/1.1
Authorization: Bearer <user_a_token>

# 2. Modify ID to another user's resource
GET /api/accounts/ACC-002/transactions HTTP/1.1
Authorization: Bearer <user_a_token>

# 3. If data returns → BOLA vulnerability confirmed

# Automated Testing: ID enumeration
for id in {1..1000}; do
  response=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "https://api.example.com/users/$id/profile")
  if [[ $response != *"Not found"* ]]; then
    echo "Accessible: $id"
  fi
done
```

---

## API2:2023 - Broken Authentication

### Overview

Broken Authentication occurs when authentication mechanisms are implemented incorrectly, allowing attackers to compromise credentials, tokens, or exploit implementation flaws to assume other users' identities.

```
┌─────────────────────────────────────────────────────────────────────┐
│                Authentication Attack Vectors                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CREDENTIAL ATTACKS                                                  │
│  ├─ Brute force (weak rate limiting)                                │
│  ├─ Credential stuffing (leaked credentials)                        │
│  ├─ Password spraying (common passwords)                            │
│  └─ Default credentials                                             │
│                                                                      │
│  TOKEN ATTACKS                                                       │
│  ├─ JWT algorithm confusion (HS256 vs RS256)                        │
│  ├─ Token theft (XSS, logging exposure)                             │
│  ├─ Weak token generation                                           │
│  ├─ Missing token expiration                                        │
│  └─ Token reuse after logout                                        │
│                                                                      │
│  IMPLEMENTATION FLAWS                                                │
│  ├─ Sensitive data in URL (tokens in query strings)                 │
│  ├─ Missing authentication on endpoints                             │
│  ├─ Weak password reset flows                                       │
│  └─ Insecure "remember me" functionality                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Vulnerable Patterns

```javascript
// ❌ VULNERABLE: Multiple issues
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Issue 1: No rate limiting
  // Issue 2: Reveals if username exists
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Username not found' });
  }
  
  // Issue 3: Weak password comparison (timing attack)
  if (password !== user.password) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  // Issue 4: Token never expires
  const token = jwt.sign({ userId: user.id }, SECRET);
  
  // Issue 5: Token in response body only (no httpOnly cookie)
  res.json({ token });
});
```

```javascript
// ✅ SECURE: Proper authentication implementation
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  skipSuccessfulRequests: true
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  // Generic error message (doesn't reveal if user exists)
  const genericError = { error: 'Invalid credentials' };
  
  const user = await User.findOne({ username });
  if (!user) {
    // Constant-time delay to prevent timing attacks
    await bcrypt.compare(password, '$2b$10$fakehash');
    return res.status(401).json(genericError);
  }
  
  // Secure password comparison
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    await recordFailedAttempt(user.id);
    return res.status(401).json(genericError);
  }
  
  // Short-lived access token
  const accessToken = jwt.sign(
    { userId: user.id, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: '15m', algorithm: 'RS256' }
  );
  
  // Longer-lived refresh token (stored securely)
  const refreshToken = generateSecureToken();
  await storeRefreshToken(user.id, refreshToken);
  
  // HttpOnly, Secure cookies
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  
  res.json({ accessToken });
});
```

### JWT Security Best Practices

| Practice | Description |
|----------|-------------|
| **Use RS256** | Asymmetric signing prevents secret exposure |
| **Validate Algorithm** | Reject tokens with unexpected algorithms |
| **Short Expiration** | Access tokens: 15 min, Refresh: 7 days |
| **Include Claims** | iss, aud, exp, iat, jti (token ID) |
| **Secure Storage** | HttpOnly cookies for refresh tokens |
| **Token Revocation** | Maintain blocklist for logout/compromise |

---

## API3:2023 - Broken Object Property Level Authorization

### Overview

This combines two 2019 risks: **Excessive Data Exposure** and **Mass Assignment**. It occurs when APIs expose sensitive object properties or allow unauthorized modification of properties.

```
┌─────────────────────────────────────────────────────────────────────┐
│           Object Property Level Authorization Issues                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  EXCESSIVE DATA EXPOSURE (Reading)                                   │
│  ├─ API returns entire object including sensitive fields            │
│  ├─ Client-side filtering of sensitive data                         │
│  └─ Internal fields exposed (isAdmin, passwordHash, etc.)           │
│                                                                      │
│  Example Response (Vulnerable):                                      │
│  {                                                                   │
│    "id": "user-123",                                                │
│    "name": "John Doe",                                              │
│    "email": "john@example.com",                                     │
│    "ssn": "123-45-6789",          ← Sensitive!                      │
│    "passwordHash": "abc123...",   ← Sensitive!                      │
│    "isAdmin": false,              ← Internal!                       │
│    "creditScore": 750             ← Sensitive!                      │
│  }                                                                   │
│                                                                      │
│  MASS ASSIGNMENT (Writing)                                           │
│  ├─ API binds all request parameters to object                      │
│  ├─ Attacker sets fields they shouldn't control                     │
│  └─ Privilege escalation via property manipulation                  │
│                                                                      │
│  Example Attack:                                                     │
│  PUT /api/users/me                                                  │
│  {                                                                   │
│    "name": "John Doe",                                              │
│    "email": "john@example.com",                                     │
│    "isAdmin": true,               ← Attacker-added!                 │
│    "accountBalance": 999999       ← Attacker-added!                 │
│  }                                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Vulnerable vs Secure Code

```python
# ❌ VULNERABLE: Mass assignment
@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    
    # Blindly updates ALL fields from request
    for key, value in request.json.items():
        setattr(user, key, value)  # Mass assignment!
    
    db.session.commit()
    
    # Returns entire object including sensitive fields
    return jsonify(user.__dict__)  # Excessive data exposure!
```

```python
# ✅ SECURE: Explicit field handling
from marshmallow import Schema, fields, EXCLUDE

class UserUpdateSchema(Schema):
    class Meta:
        unknown = EXCLUDE  # Ignore unknown fields
    
    name = fields.Str(required=False)
    email = fields.Email(required=False)
    # Note: isAdmin, passwordHash NOT included

class UserResponseSchema(Schema):
    id = fields.Str()
    name = fields.Str()
    email = fields.Email()
    created_at = fields.DateTime()
    # Note: Sensitive fields NOT included

@app.route('/api/users/<user_id>', methods=['PUT'])
@require_authentication
def update_user(user_id, current_user):
    # Authorization check
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403
    
    # Validate and filter input
    schema = UserUpdateSchema()
    try:
        validated_data = schema.load(request.json)
    except ValidationError as e:
        return jsonify({'errors': e.messages}), 400
    
    user = User.query.get(user_id)
    
    # Update only allowed fields
    for key, value in validated_data.items():
        setattr(user, key, value)
    
    db.session.commit()
    
    # Return only safe fields
    response_schema = UserResponseSchema()
    return jsonify(response_schema.dump(user))
```

### Prevention Strategies

| Attack Type | Prevention |
|-------------|------------|
| **Excessive Data Exposure** | Use DTOs/response schemas, never return raw objects |
| **Mass Assignment** | Allowlist updateable fields, use validation schemas |
| **Both** | Implement field-level authorization checks |

---

## API4:2023 - Unrestricted Resource Consumption

### Overview

APIs that don't limit resource consumption are vulnerable to Denial of Service (DoS) attacks, financial damage (pay-per-request billing), and performance degradation.

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Resource Consumption Attacks                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ATTACK VECTORS                          IMPACT                      │
│  ├─ No rate limiting                     ├─ Service unavailability  │
│  ├─ Large payload uploads                ├─ Infrastructure costs    │
│  ├─ Complex query parameters             ├─ Database overload       │
│  ├─ Pagination abuse (page=999999)       ├─ Memory exhaustion       │
│  ├─ GraphQL depth/complexity             ├─ CPU exhaustion          │
│  └─ Concurrent request flooding          └─ Cascading failures      │
│                                                                      │
│  RESOURCE TYPES                                                      │
│  ├─ CPU: Complex queries, regex, crypto operations                  │
│  ├─ Memory: Large responses, file processing                        │
│  ├─ Storage: File uploads, logs                                     │
│  ├─ Network: Bandwidth, connections                                 │
│  └─ Cost: Third-party API calls, cloud resources                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation Examples

```python
# ❌ VULNERABLE: No limits
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q')
    limit = int(request.args.get('limit', 1000000))  # No max!
    
    # Complex regex from user input
    import re
    pattern = re.compile(query)  # ReDoS vulnerability!
    
    results = db.query(Item).filter(
        Item.name.op('~')(query)
    ).limit(limit).all()
    
    return jsonify([r.to_dict() for r in results])

@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files['file']  # No size limit!
    file.save(f'/uploads/{file.filename}')
    return jsonify({'status': 'uploaded'})
```

```python
# ✅ SECURE: Proper resource limits
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration
MAX_PAGE_SIZE = 100
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
QUERY_TIMEOUT = 5  # seconds

@app.route('/api/search', methods=['GET'])
@limiter.limit("30 per minute")
def search():
    query = request.args.get('q', '')
    
    # Validate query length
    if len(query) > 100:
        return jsonify({'error': 'Query too long'}), 400
    
    # Sanitize for regex (or use parameterized search)
    query = re.escape(query)
    
    # Enforce pagination limits
    limit = min(int(request.args.get('limit', 20)), MAX_PAGE_SIZE)
    offset = int(request.args.get('offset', 0))
    
    # Query with timeout
    with db.session.execute(
        text("SET statement_timeout = :timeout"),
        {'timeout': QUERY_TIMEOUT * 1000}
    ):
        results = db.query(Item).filter(
            Item.name.ilike(f'%{query}%')
        ).limit(limit).offset(offset).all()
    
    return jsonify({
        'results': [r.to_dict() for r in results],
        'limit': limit,
        'offset': offset
    })

@app.route('/api/upload', methods=['POST'])
@limiter.limit("5 per hour")
def upload():
    # Check content length header
    if request.content_length > MAX_UPLOAD_SIZE:
        return jsonify({'error': 'File too large'}), 413
    
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file provided'}), 400
    
    # Validate file type
    allowed_types = {'image/jpeg', 'image/png', 'application/pdf'}
    if file.content_type not in allowed_types:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Stream and limit actual read
    content = file.read(MAX_UPLOAD_SIZE + 1)
    if len(content) > MAX_UPLOAD_SIZE:
        return jsonify({'error': 'File too large'}), 413
    
    # Save securely
    filename = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    with open(save_path, 'wb') as f:
        f.write(content)
    
    return jsonify({'status': 'uploaded', 'filename': filename})
```

### Rate Limiting Strategies

| Strategy | Use Case | Example |
|----------|----------|---------|
| **Fixed Window** | Simple rate limiting | 100 requests per hour |
| **Sliding Window** | Smoother distribution | 100 requests per rolling hour |
| **Token Bucket** | Burst allowance | 10 tokens, 1 added per second |
| **Per-User** | Authenticated APIs | 1000 requests/day per API key |
| **Per-Endpoint** | Sensitive operations | 5 password resets per hour |
| **Cost-Based** | GraphQL complexity | Query cost ≤ 1000 points |

---

## API5:2023 - Broken Function Level Authorization

### Overview

Broken Function Level Authorization (BFLA) occurs when users can access administrative or privileged functions they shouldn't have access to. Unlike BOLA (object access), BFLA is about accessing unauthorized functions/endpoints.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BFLA Attack Patterns                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  COMMON VULNERABILITIES                                              │
│  ├─ Admin endpoints accessible to regular users                     │
│  │   └─ /api/admin/users → No role check                           │
│  ├─ HTTP method bypass                                              │
│  │   └─ GET blocked, but DELETE works                              │
│  ├─ URL path manipulation                                           │
│  │   └─ /api/users/123 → /api/users/123/admin                      │
│  └─ Parameter-based privilege escalation                            │
│      └─ POST /api/action?admin=true                                │
│                                                                      │
│  ATTACK FLOW                                                         │
│  1. Discover admin/privileged endpoints                             │
│  2. Attempt access with regular user credentials                    │
│  3. If no function-level check → Privilege escalation              │
│                                                                      │
│  IMPACT                                                              │
│  ├─ Unauthorized data modification                                  │
│  ├─ User management (create/delete accounts)                        │
│  ├─ System configuration changes                                    │
│  └─ Complete application takeover                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Vulnerable vs Secure Code

```python
# ❌ VULNERABLE: No function-level authorization
@app.route('/api/admin/users', methods=['GET'])
@require_authentication  # Only checks authentication, not authorization
def list_all_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@require_authentication
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})
```

```python
# ✅ SECURE: Role-based function authorization
from functools import wraps

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            if current_user.role not in allowed_roles:
                # Log the unauthorized attempt
                log_security_event(
                    event_type='UNAUTHORIZED_FUNCTION_ACCESS',
                    user_id=current_user.id,
                    endpoint=request.endpoint,
                    method=request.method
                )
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/admin/users', methods=['GET'])
@require_role('admin', 'superadmin')
def list_all_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@require_role('superadmin')  # More restrictive
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Additional check: can't delete self
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    log_audit_event('USER_DELETED', target_user=user_id, by_user=current_user.id)
    return jsonify({'status': 'deleted'})
```

### Prevention Strategies

| Strategy | Description |
|----------|-------------|
| **RBAC Implementation** | Define roles and permissions clearly |
| **Deny by Default** | Block all access unless explicitly allowed |
| **Centralized Authorization** | Use middleware/guards, not scattered checks |
| **API Gateway Policies** | Enforce authorization at gateway level |
| **Regular Audits** | Review endpoint permissions periodically |

---

## API6:2023 - Unrestricted Access to Sensitive Business Flows

### Overview

**New in 2023.** This risk occurs when APIs expose business flows that can be abused through automation, causing harm when used excessively. Unlike technical vulnerabilities, this exploits legitimate functionality.

```
┌─────────────────────────────────────────────────────────────────────┐
│              Business Flow Abuse Scenarios                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SCENARIO 1: Ticket Scalping                                        │
│  ├─ Normal: User buys 2 concert tickets                             │
│  └─ Abuse: Bot buys 1000 tickets in seconds, resells at markup     │
│                                                                      │
│  SCENARIO 2: Referral Program Abuse                                 │
│  ├─ Normal: User refers friends, gets credit                        │
│  └─ Abuse: Script creates fake accounts, harvests referral credits │
│                                                                      │
│  SCENARIO 3: Price Scraping                                         │
│  ├─ Normal: User checks prices for a few products                   │
│  └─ Abuse: Competitor scrapes entire catalog continuously          │
│                                                                      │
│  SCENARIO 4: Account Enumeration                                    │
│  ├─ Normal: "Forgot password" checks if email exists                │
│  └─ Abuse: Attacker maps valid accounts for targeted attacks       │
│                                                                      │
│  SCENARIO 5: Inventory Hoarding                                     │
│  ├─ Normal: User adds items to cart                                 │
│  └─ Abuse: Bots hold inventory in carts, creating false scarcity   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Prevention Strategies

```python
# Mitigation techniques for business flow abuse

from datetime import datetime, timedelta
import hashlib

class BusinessFlowProtection:
    
    def __init__(self):
        self.redis = Redis()
    
    # 1. Device Fingerprinting
    def get_device_fingerprint(self, request):
        components = [
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.remote_addr
        ]
        return hashlib.sha256('|'.join(components).encode()).hexdigest()
    
    # 2. Velocity Checking
    def check_velocity(self, user_id, action, limit, window_seconds):
        key = f"velocity:{action}:{user_id}"
        count = self.redis.incr(key)
        if count == 1:
            self.redis.expire(key, window_seconds)
        return count <= limit
    
    # 3. CAPTCHA Triggering
    def should_trigger_captcha(self, user_id, action):
        # Trigger after suspicious patterns
        suspicious_score = self.get_suspicious_score(user_id, action)
        return suspicious_score > 0.7
    
    # 4. Human Verification for High-Value Actions
    def verify_human_for_purchase(self, user_id, item_value):
        if item_value > 500:  # High-value threshold
            return self.require_step_up_auth(user_id)
        return True

# Implementation in endpoint
@app.route('/api/checkout', methods=['POST'])
@require_authentication
def checkout():
    protection = BusinessFlowProtection()
    
    # Check velocity
    if not protection.check_velocity(
        current_user.id, 
        'checkout', 
        limit=3, 
        window_seconds=300  # 3 checkouts per 5 minutes
    ):
        return jsonify({'error': 'Too many checkout attempts'}), 429
    
    # Check for bot patterns
    if protection.should_trigger_captcha(current_user.id, 'checkout'):
        return jsonify({
            'error': 'Verification required',
            'captcha_required': True
        }), 428
    
    # Device fingerprint tracking
    fingerprint = protection.get_device_fingerprint(request)
    if is_known_bad_fingerprint(fingerprint):
        return jsonify({'error': 'Request blocked'}), 403
    
    # Proceed with checkout
    return process_checkout(request.json)
```

### Detection & Prevention Matrix

| Technique | Description | When to Use |
|-----------|-------------|-------------|
| **Rate Limiting** | Limit requests per time window | All sensitive flows |
| **CAPTCHA** | Human verification | After suspicious patterns |
| **Device Fingerprinting** | Track device characteristics | High-value transactions |
| **Behavioral Analysis** | Detect non-human patterns | Real-time monitoring |
| **Queue Systems** | Process requests sequentially | Limited inventory |
| **Step-Up Auth** | Additional verification | Sensitive operations |

---

## API7:2023 - Server Side Request Forgery

### Overview

**New in 2023.** Server-Side Request Forgery (SSRF) occurs when an API fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server to make requests to unintended destinations.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SSRF Attack Flow                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                         ATTACKER                                     │
│                            │                                         │
│                            │ POST /api/fetch-url                    │
│                            │ { "url": "http://169.254.169.254/..." }│
│                            ▼                                         │
│  ┌─────────────────────────────────────────────────────┐            │
│  │              VULNERABLE API SERVER                   │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  def fetch_url(url):                        │    │            │
│  │  │      response = requests.get(url)  # No    │    │            │
│  │  │      return response.text          # validation  │            │
│  │  └─────────────────────────────────────────────┘    │            │
│  └──────────────────────────┬──────────────────────────┘            │
│                             │                                        │
│                             │ Server makes request                  │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────┐            │
│  │           INTERNAL TARGETS                          │            │
│  │  ├─ Cloud Metadata (AWS: 169.254.169.254)          │            │
│  │  │   └─ Exposes: IAM credentials, instance data    │            │
│  │  ├─ Internal Services (http://internal-api:8080)   │            │
│  │  │   └─ Exposes: Internal APIs, databases          │            │
│  │  ├─ Localhost (http://127.0.0.1:6379)              │            │
│  │  │   └─ Exposes: Redis, databases, admin panels    │            │
│  │  └─ File System (file:///etc/passwd)               │            │
│  │      └─ Exposes: System files                      │            │
│  └─────────────────────────────────────────────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Cloud Metadata Endpoints

| Cloud Provider | Metadata URL | Sensitive Data |
|----------------|--------------|----------------|
| AWS | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance ID |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| Azure | `http://169.254.169.254/metadata/instance` | Managed identity tokens |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | Droplet metadata |

### Vulnerable vs Secure Code

```python
# ❌ VULNERABLE: No URL validation
@app.route('/api/fetch-preview', methods=['POST'])
def fetch_preview():
    url = request.json.get('url')
    
    # Directly fetches any URL!
    response = requests.get(url, timeout=10)
    
    return jsonify({
        'content': response.text[:1000],
        'status': response.status_code
    })
```

```python
# ✅ SECURE: SSRF protection
from urllib.parse import urlparse
import ipaddress
import socket

class SSRFProtection:
    
    # Blocklist of internal/sensitive IP ranges
    BLOCKED_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('10.0.0.0/8'),       # Private
        ipaddress.ip_network('172.16.0.0/12'),    # Private
        ipaddress.ip_network('192.168.0.0/16'),   # Private
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local (AWS metadata!)
        ipaddress.ip_network('::1/128'),          # IPv6 loopback
        ipaddress.ip_network('fc00::/7'),         # IPv6 private
    ]
    
    ALLOWED_SCHEMES = {'http', 'https'}
    BLOCKED_PORTS = {22, 23, 25, 445, 3389, 6379, 27017}
    
    @classmethod
    def validate_url(cls, url):
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            raise ValueError("Invalid URL format")
        
        # Check scheme
        if parsed.scheme not in cls.ALLOWED_SCHEMES:
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        # Check port
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port in cls.BLOCKED_PORTS:
            raise ValueError(f"Port not allowed: {port}")
        
        # Resolve hostname to IP
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("No hostname provided")
        
        try:
            # Resolve before making request to prevent DNS rebinding
            ip_address = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_address)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {hostname}")
        
        # Check against blocked ranges
        for network in cls.BLOCKED_RANGES:
            if ip in network:
                raise ValueError(f"IP address not allowed: {ip_address}")
        
        return True

@app.route('/api/fetch-preview', methods=['POST'])
@limiter.limit("10 per minute")
def fetch_preview():
    url = request.json.get('url')
    
    # Validate URL
    try:
        SSRFProtection.validate_url(url)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    # Fetch with additional protections
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,  # Prevent redirect-based bypass
            headers={'User-Agent': 'PreviewBot/1.0'}
        )
        
        # Don't follow redirects automatically - validate each hop
        if response.is_redirect:
            return jsonify({'error': 'Redirects not allowed'}), 400
        
        return jsonify({
            'content': response.text[:1000],
            'status': response.status_code
        })
    except requests.RequestException as e:
        return jsonify({'error': 'Failed to fetch URL'}), 502
```

### Prevention Summary

| Layer | Protection |
|-------|------------|
| **Input Validation** | Allowlist schemes, validate hostnames |
| **DNS Resolution** | Resolve before request, block internal IPs |
| **Network** | Segment services, firewall egress traffic |
| **Runtime** | Disable redirects, enforce timeouts |
| **Cloud** | Use IMDSv2, restrict metadata access |

---

## API8:2023 - Security Misconfiguration

### Overview

Security misconfiguration is a broad category covering insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, verbose error messages, and unnecessary features.

```
┌─────────────────────────────────────────────────────────────────────┐
│              Common API Misconfigurations                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TRANSPORT SECURITY                                                  │
│  ├─ Missing TLS/HTTPS enforcement                                   │
│  ├─ Outdated TLS versions (TLS 1.0, 1.1)                           │
│  ├─ Weak cipher suites                                              │
│  └─ Missing HSTS headers                                            │
│                                                                      │
│  CORS CONFIGURATION                                                  │
│  ├─ Access-Control-Allow-Origin: *                                  │
│  ├─ Reflecting Origin header without validation                     │
│  └─ Allowing credentials with wildcard origin                       │
│                                                                      │
│  ERROR HANDLING                                                      │
│  ├─ Stack traces in responses                                       │
│  ├─ Database errors exposed                                         │
│  └─ Debug mode in production                                        │
│                                                                      │
│  HTTP HEADERS                                                        │
│  ├─ Missing X-Content-Type-Options                                  │
│  ├─ Missing X-Frame-Options                                         │
│  ├─ Missing Content-Security-Policy                                 │
│  └─ Server version disclosure                                       │
│                                                                      │
│  API FEATURES                                                        │
│  ├─ Unnecessary HTTP methods enabled                                │
│  ├─ Debug endpoints in production                                   │
│  ├─ Default credentials                                             │
│  └─ GraphQL introspection enabled                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Secure Configuration Examples

```python
# Secure Flask/Python API configuration

from flask import Flask
from flask_cors import CORS
from flask_talisman import Talisman

app = Flask(__name__)

# ✅ CORS: Explicit origin allowlist
CORS(app, origins=[
    'https://app.example.com',
    'https://admin.example.com'
], supports_credentials=True)

# ✅ Security headers via Talisman
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'"
    }
)

# ✅ Secure error handling
@app.errorhandler(Exception)
def handle_exception(e):
    # Log full error for debugging
    app.logger.error(f"Unhandled exception: {e}", exc_info=True)
    
    # Return generic message to client
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    
    return jsonify({'error': 'Internal server error'}), 500

# ✅ Disable debug in production
app.config['DEBUG'] = False
app.config['TESTING'] = False

# ✅ Hide server information
@app.after_request
def remove_server_header(response):
    response.headers.pop('Server', None)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

### Configuration Checklist

| Category | Secure Configuration |
|----------|---------------------|
| **TLS** | TLS 1.2+, strong ciphers, valid certificates |
| **CORS** | Explicit origin allowlist, no wildcards with credentials |
| **Headers** | HSTS, X-Content-Type-Options, X-Frame-Options, CSP |
| **Errors** | Generic messages, no stack traces, proper logging |
| **Features** | Disable unused HTTP methods, no debug endpoints |
| **Defaults** | Change default credentials, disable default accounts |

---

## API9:2023 - Improper Inventory Management

### Overview

APIs often expose more endpoints than traditional web applications. Without proper inventory management, organizations lose track of API versions, deprecated endpoints, and shadow APIs, creating security blind spots.

```
┌─────────────────────────────────────────────────────────────────────┐
│              API Inventory Management Issues                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SHADOW APIs                                                         │
│  ├─ Undocumented endpoints created by developers                    │
│  ├─ Test/debug endpoints left in production                         │
│  └─ Forgotten internal APIs exposed externally                      │
│                                                                      │
│  DEPRECATED VERSIONS                                                 │
│  ├─ /api/v1/users (deprecated, but still active)                   │
│  ├─ /api/v2/users (current, secured)                               │
│  └─ Old version may lack security controls                         │
│                                                                      │
│  ENVIRONMENT DRIFT                                                   │
│  ├─ Development APIs accessible from production                     │
│  ├─ Staging environments with production data                       │
│  └─ Different security configurations per environment              │
│                                                                      │
│  DOCUMENTATION GAPS                                                  │
│  ├─ Endpoints exist but aren't in OpenAPI spec                     │
│  ├─ Documented behavior differs from actual                        │
│  └─ Missing authentication requirements                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Prevention Strategies

```yaml
# API Inventory Management Process

1. Discovery:
  - Automated API discovery tools
  - Traffic analysis
  - Code scanning for route definitions
  - Regular security assessments

2. Documentation:
  - OpenAPI/Swagger specifications
  - Version in URL or header
  - Deprecation dates clearly marked
  - Authentication requirements documented

3. Version Management:
  # Example versioning strategy
  /api/v1/users  # Deprecated: 2024-01-01, Sunset: 2024-07-01
  /api/v2/users  # Current stable
  /api/v3/users  # Beta

4. Lifecycle Policies:
  - Maximum API version age: 2 years
  - Deprecation notice: 6 months before sunset
  - Mandatory migration path documented
  - Automatic sunset enforcement

5. Monitoring:
  - Track usage of all API versions
  - Alert on deprecated endpoint usage
  - Identify undocumented endpoint access
  - Monitor for shadow API creation
```

### API Inventory Template

| Endpoint | Version | Status | Owner | Auth | Last Audit |
|----------|---------|--------|-------|------|------------|
| /api/v2/users | 2.0 | Active | Team A | OAuth2 | 2024-12-01 |
| /api/v1/users | 1.0 | Deprecated | Team A | API Key | 2024-06-01 |
| /api/orders | 1.0 | Active | Team B | OAuth2 | 2024-11-15 |
| /internal/health | - | Internal | Platform | None | 2024-12-15 |

---

## API10:2023 - Unsafe Consumption of APIs

### Overview

**New in 2023.** Developers often trust data from third-party APIs more than user input. This can lead to vulnerabilities when the third-party API is compromised, returns malicious data, or is exploited via SSRF.

```
┌─────────────────────────────────────────────────────────────────────┐
│              Unsafe API Consumption Risks                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TRUST ASSUMPTIONS                                                   │
│  ├─ "Third-party API responses are safe"                           │
│  ├─ "Partner APIs wouldn't send malicious data"                    │
│  └─ "Established services are secure"                              │
│                                                                      │
│  ATTACK SCENARIOS                                                    │
│                                                                      │
│  1. Compromised Third-Party                                         │
│     Third-party API gets hacked → Returns malicious payloads       │
│     Your app trusts the response → SQL injection, XSS, etc.        │
│                                                                      │
│  2. SSRF via Third-Party                                            │
│     Your API → Third-party API → Attacker's server                 │
│     Third-party redirects to internal resources                    │
│                                                                      │
│  3. Supply Chain Attack                                             │
│     Attacker compromises API dependency                            │
│     Malicious data propagates through your system                  │
│                                                                      │
│  4. Data Injection                                                   │
│     Third-party returns data with embedded payloads                │
│     <script>alert('XSS')</script> in product name                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Secure Third-Party API Consumption

```python
# ❌ VULNERABLE: Trusting third-party data
@app.route('/api/products/<product_id>')
def get_product(product_id):
    # Fetch from third-party
    response = requests.get(
        f'{PARTNER_API}/products/{product_id}',
        headers={'Authorization': f'Bearer {PARTNER_API_KEY}'}
    )
    
    # Directly store and return without validation
    product_data = response.json()
    
    # Dangerous: Third-party data directly in SQL
    db.execute(
        f"INSERT INTO products (name) VALUES ('{product_data['name']}')"
    )
    
    # Dangerous: Third-party data directly in response
    return jsonify(product_data)
```

```python
# ✅ SECURE: Validating third-party data
from marshmallow import Schema, fields, validate, ValidationError
from markupsafe import escape

class ThirdPartyProductSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(max=200))
    price = fields.Float(required=True, validate=validate.Range(min=0))
    description = fields.Str(validate=validate.Length(max=5000))
    category = fields.Str(validate=validate.OneOf(['electronics', 'clothing', 'food']))

@app.route('/api/products/<product_id>')
def get_product(product_id):
    # Validate product_id format
    if not re.match(r'^[a-zA-Z0-9-]{1,50}$', product_id):
        return jsonify({'error': 'Invalid product ID'}), 400
    
    # Fetch from third-party with timeout and error handling
    try:
        response = requests.get(
            f'{PARTNER_API}/products/{product_id}',
            headers={'Authorization': f'Bearer {PARTNER_API_KEY}'},
            timeout=5
        )
        response.raise_for_status()
    except requests.RequestException as e:
        app.logger.error(f"Third-party API error: {e}")
        return jsonify({'error': 'Unable to fetch product'}), 502
    
    # Validate third-party response structure
    schema = ThirdPartyProductSchema()
    try:
        validated_data = schema.load(response.json())
    except ValidationError as e:
        app.logger.warning(f"Invalid third-party data: {e.messages}")
        return jsonify({'error': 'Invalid product data'}), 502
    
    # Sanitize string fields for XSS prevention
    validated_data['name'] = escape(validated_data['name'])
    validated_data['description'] = escape(validated_data.get('description', ''))
    
    # Use parameterized queries
    db.execute(
        "INSERT INTO products (name, price) VALUES (:name, :price)",
        {'name': validated_data['name'], 'price': validated_data['price']}
    )
    
    return jsonify(validated_data)
```

### Third-Party API Security Checklist

| Check | Description |
|-------|-------------|
| **Input Validation** | Validate all third-party responses against schema |
| **Output Encoding** | Sanitize data before rendering/storing |
| **Transport Security** | Verify HTTPS, validate certificates |
| **Authentication** | Secure API key storage, rotate regularly |
| **Rate Limiting** | Implement circuit breakers, handle failures |
| **Monitoring** | Log third-party interactions, alert on anomalies |

---

## Changes from 2019 to 2023

```
┌─────────────────────────────────────────────────────────────────────┐
│                    2019 → 2023 Changes                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  UNCHANGED (Same position)                                          │
│  ├─ API1: Broken Object Level Authorization (BOLA)                  │
│  ├─ API2: Broken Authentication (renamed from "User Auth")          │
│  ├─ API5: Broken Function Level Authorization (BFLA)                │
│  └─ API8: Security Misconfiguration                                 │
│                                                                      │
│  MERGED                                                              │
│  ├─ API3:2019 Excessive Data Exposure    ─┐                        │
│  │                                         ├→ API3:2023 Broken      │
│  └─ API6:2019 Mass Assignment            ─┘   Object Property Auth  │
│                                                                      │
│  RENAMED                                                             │
│  ├─ API4:2019 Lack of Resources → API4:2023 Unrestricted Resource  │
│  └─ API9:2019 Improper Assets  → API9:2023 Improper Inventory      │
│                                                                      │
│  NEW IN 2023                                                         │
│  ├─ API6:2023 Unrestricted Access to Sensitive Business Flows      │
│  ├─ API7:2023 Server Side Request Forgery (SSRF)                   │
│  └─ API10:2023 Unsafe Consumption of APIs                          │
│                                                                      │
│  REMOVED                                                             │
│  ├─ API7:2019 Security Misconfiguration (moved)                    │
│  ├─ API10:2019 Insufficient Logging & Monitoring                   │
│  └─ Injection (covered elsewhere, less API-specific)               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## API Security Testing Checklist

### Pre-Deployment Checklist

| Category | Check | Status |
|----------|-------|--------|
| **Authentication** | | |
| | Strong password policy enforced | ☐ |
| | JWT tokens use RS256 with short expiry | ☐ |
| | Rate limiting on login endpoints | ☐ |
| | Account lockout after failed attempts | ☐ |
| | Secure password reset flow | ☐ |
| **Authorization** | | |
| | Object-level authorization on all endpoints | ☐ |
| | Function-level authorization enforced | ☐ |
| | Property-level filtering on responses | ☐ |
| | Mass assignment protection | ☐ |
| **Input Validation** | | |
| | Schema validation on all inputs | ☐ |
| | SQL injection prevention | ☐ |
| | XSS prevention | ☐ |
| | Path traversal prevention | ☐ |
| **Resource Protection** | | |
| | Rate limiting implemented | ☐ |
| | Pagination enforced | ☐ |
| | File upload size limits | ☐ |
| | Query complexity limits (GraphQL) | ☐ |
| **Configuration** | | |
| | HTTPS enforced | ☐ |
| | CORS properly configured | ☐ |
| | Security headers present | ☐ |
| | Debug mode disabled | ☐ |
| | Error messages don't leak info | ☐ |
| **Inventory** | | |
| | All endpoints documented | ☐ |
| | Deprecated versions tracked | ☐ |
| | No shadow APIs in production | ☐ |

### Testing Tools

| Tool | Purpose | Type |
|------|---------|------|
| **Burp Suite** | Manual testing, proxy | Commercial/Free |
| **OWASP ZAP** | Automated scanning | Open Source |
| **Postman** | API testing, collections | Free/Commercial |
| **Nuclei** | Vulnerability scanning | Open Source |
| **Ffuf** | Fuzzing, enumeration | Open Source |
| **sqlmap** | SQL injection testing | Open Source |

---

## Resources

### Official OWASP Resources
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Testing Resources
- [OWASP API Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [API Security Empire](https://github.com/Cyber-Guy1/API-SecurityEmpire)

### Learning Platforms
- [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
- [OWASP crAPI (Completely Ridiculous API)](https://github.com/OWASP/crAPI)
- [VAmPI (Vulnerable API)](https://github.com/erev0s/VAmPI)
