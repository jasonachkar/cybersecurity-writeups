# Mitigating API Vulnerabilities in .NET (C#)

ASP.NET Core provides robust, built-in mechanisms to defend against the OWASP API Security Top 10. Below are the key strategies and code examples for securing a .NET API.

---

## 1. Preventing BOLA / IDOR (API1:2023)

Never trust the ID provided in the URL. Always cross-reference it with the identity of the currently authenticated user.

**Insecure:**
```csharp
[HttpGet("{orderId}")]
public async Task<IActionResult> GetOrder(int orderId)
{
    // VULNERABLE: Any authenticated user can pass any orderId
    var order = await _context.Orders.FindAsync(orderId);
    return Ok(order);
}
```

**Secure:**
```csharp
[HttpGet("{orderId}")]
public async Task<IActionResult> GetOrder(int orderId)
{
    // Extract the User's ID from the JWT Claims
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    
    // SECURE: Filter the query to ensure the order belongs to this specific user
    var order = await _context.Orders
        .FirstOrDefaultAsync(o => o.Id == orderId && o.UserId == userId);
        
    if (order == null) return NotFound();
    return Ok(order);
}
```

## 2. Preventing Mass Assignment (API3:2023)

Never bind API request bodies directly to your Entity Framework database models. Attackers can inject fields like `"IsAdmin": true`.

**Use Data Transfer Objects (DTOs):**
```csharp
// Only include fields the user is explicitly allowed to update
public class UpdateProfileDto
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    // Note: IsAdmin or Balance is intentionally omitted
}

[HttpPut("profile")]
public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDto dto)
{
    var user = await _context.Users.FindAsync(CurrentUserId);
    
    // Map only the safe fields from the DTO to the actual entity
    user.FirstName = dto.FirstName;
    user.LastName = dto.LastName;
    
    await _context.SaveChangesAsync();
    return Ok();
}
```

## 3. Rate Limiting (API4:2023)

Use the built-in ASP.NET Core Rate Limiting middleware (introduced in .NET 7).

```csharp
// Program.cs
builder.Services.AddRateLimiter(options => {
    options.AddFixedWindowLimiter("Basic", opt => {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 2;
    });
});

var app = builder.Build();
app.UseRateLimiter(); // Apply middleware

// In Controller
[EnableRateLimiting("Basic")]
[HttpGet("data")]
public IActionResult GetData() { ... }
```

## 4. Preventing Security Misconfigurations (API8:2023)

### CORS (Cross-Origin Resource Sharing)
Never use `.AllowAnyOrigin()` in production. Always specify exact domains.
```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("StrictPolicy", policy =>
    {
        policy.WithOrigins("https://myfrontend.com")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
```

### Hiding Stack Traces
Ensure detailed exceptions are only returned in the Development environment.
```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    // Return a generic JSON error message in production
    app.UseExceptionHandler("/error");
    // Enforce HTTPS
    app.UseHsts();
}
```
