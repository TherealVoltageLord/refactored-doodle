import express from "express";
import cors from "cors";
import { v4 as uuid } from "uuid";
import { generateCaptcha } from "./captcha.js";

const app = express();

// Middleware
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:8080',
    'http://127.0.0.1:8080'
  ],
  credentials: false,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files for demo
app.use(express.static('public'));

// Rate limiting store
const requestCounts = new Map();
const captchaStore = new Map();

// Configuration
const config = {
  rateLimit: {
    captchaGeneration: { windowMs: 15 * 60 * 1000, max: 100 },
    captchaValidation: { windowMs: 15 * 60 * 1000, max: 200 },
    general: { windowMs: 15 * 60 * 1000, max: 500 }
  },
  captcha: {
    expiration: 10 * 60 * 1000, // 10 minutes
    maxAttempts: 3,
    cleanupInterval: 5 * 60 * 1000 // 5 minutes
  },
  security: {
    maxAnswerLength: 10,
    allowedDifficulties: ['easy', 'medium', 'hard', 'extreme']
  }
};

// Advanced rate limiting middleware
const advancedRateLimit = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const path = req.path;
  const now = Date.now();
  
  let configKey = 'general';
  if (path === '/api/captcha') configKey = 'captchaGeneration';
  else if (path === '/api/validate-captcha') configKey = 'captchaValidation';
  
  const limitConfig = config.rateLimit[configKey];
  const windowStart = now - limitConfig.windowMs;
  const key = `${ip}:${configKey}`;
  
  if (!requestCounts.has(key)) {
    requestCounts.set(key, []);
  }

  const requests = requestCounts.get(key).filter(time => time > windowStart);
  requestCounts.set(key, requests);

  if (requests.length >= limitConfig.max) {
    return res.status(429).json({ 
      success: false,
      error: "Too many requests", 
      retryAfter: Math.ceil((requests[0] + limitConfig.windowMs - now) / 1000),
      limit: limitConfig.max,
      window: `${limitConfig.windowMs / 60000} minutes`
    });
  }

  requests.push(now);
  req.rateLimitInfo = {
    remaining: limitConfig.max - requests.length,
    limit: limitConfig.max,
    reset: new Date(requests[0] + limitConfig.windowMs)
  };
  
  next();
};

app.use(advancedRateLimit);

// Bot detection middleware
const botDetection = (req, res, next) => {
  const userAgent = req.headers['user-agent'] || '';
  const accept = req.headers['accept'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  
  let botScore = 0;
  const botSignals = [];
  
  // Check for missing headers
  if (!userAgent) {
    botScore += 10;
    botSignals.push('missing-user-agent');
  }
  
  // Check for known bot user agents
  const botPatterns = [
    /bot/i, /crawl/i, /spider/i, /scrape/i, 
    /python/i, /curl/i, /wget/i, /phantom/i,
    /headless/i, /chrome-lighthouse/i
  ];
  
  botPatterns.forEach(pattern => {
    if (pattern.test(userAgent)) {
      botScore += 5;
      botSignals.push(`bot-ua-${pattern.source}`);
    }
  });
  
  // Check for suspicious accept headers
  if (!accept.includes('application/json') && !accept.includes('text/html')) {
    botScore += 3;
    botSignals.push('suspicious-accept');
  }
  
  // Check request timing (simplified)
  req._startTime = Date.now();
  
  res.on('finish', () => {
    const responseTime = Date.now() - req._startTime;
    if (responseTime < 50) { // Too fast = likely automated
      botScore += 5;
      botSignals.push('fast-response');
    }
  });

  req.botScore = botScore;
  req.botSignals = botSignals;
  next();
};

app.use(botDetection);

// Context-aware difficulty determination
function determineDifficulty(req, requestedDifficulty) {
  if (requestedDifficulty && config.security.allowedDifficulties.includes(requestedDifficulty)) {
    return requestedDifficulty;
  }
  
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /Mobi|Android|iPhone|iPad/i.test(userAgent);
  const isTablet = /Tablet|iPad/i.test(userAgent);
  
  // Adjust difficulty based on context
  if (isMobile) return 'easy';
  if (isTablet) return 'medium';
  if (req.botScore > 15) return 'hard';
  if (req.botScore > 25) return 'extreme';
  
  return 'medium'; // Default
}

// Generate CAPTCHA endpoint
app.get("/api/captcha", (req, res) => {
  try {
    const requestedDifficulty = req.query.difficulty;
    const contextDifficulty = determineDifficulty(req, requestedDifficulty);
    
    const id = uuid();
    const { question, answer, type } = generateCaptcha(contextDifficulty);

    // Store CAPTCHA data
    captchaStore.set(id, { 
      answer, 
      createdAt: Date.now(),
      expiresAt: Date.now() + config.captcha.expiration,
      attempts: 0,
      difficulty: contextDifficulty,
      type,
      context: {
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        botScore: req.botScore,
        botSignals: req.botSignals,
        requestedDifficulty,
        determinedDifficulty: contextDifficulty
      }
    });

    res.json({
      success: true,
      captchaId: id,
      question,
      type,
      difficulty: contextDifficulty,
      expiresIn: `${config.captcha.expiration / 60000} minutes`,
      rateLimit: req.rateLimitInfo
    });

  } catch (error) {
    console.error('CAPTCHA generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: "Failed to generate CAPTCHA challenge" 
    });
  }
});

// Validate CAPTCHA endpoint
app.post("/api/validate-captcha", (req, res) => {
  try {
    const { captchaId, answer } = req.body;

    // Input validation
    if (!captchaId || answer === undefined || answer === null) {
      return res.status(400).json({ 
        success: false,
        valid: false, 
        reason: "Missing captchaId or answer" 
      });
    }

    if (typeof answer === 'string' && answer.length > config.security.maxAnswerLength) {
      return res.json({ 
        success: false,
        valid: false, 
        reason: "Answer too long" 
      });
    }

    // Check if CAPTCHA exists
    if (!captchaStore.has(captchaId)) {
      return res.json({ 
        success: false,
        valid: false, 
        reason: "Invalid or expired CAPTCHA" 
      });
    }

    const captchaData = captchaStore.get(captchaId);
    
    // Check expiry
    if (Date.now() > captchaData.expiresAt) {
      captchaStore.delete(captchaId);
      return res.json({ 
        success: false,
        valid: false, 
        reason: "CAPTCHA expired" 
      });
    }

    // Check attempts
    captchaData.attempts++;
    if (captchaData.attempts > config.captcha.maxAttempts) {
      captchaStore.delete(captchaId);
      return res.json({ 
        success: false,
        valid: false, 
        reason: "Too many attempts" 
      });
    }

    // Validate answer
    const userAnswer = parseInt(answer);
    const isValid = !isNaN(userAnswer) && userAnswer === captchaData.answer;
    
    // Store validation result
    captchaData.lastValidation = {
      timestamp: Date.now(),
      valid: isValid,
      userAnswer: answer,
      actualAnswer: captchaData.answer
    };

    // One-time use - delete after successful validation
    if (isValid) {
      captchaStore.delete(captchaId);
    } else {
      // Update store with attempt count
      captchaStore.set(captchaId, captchaData);
    }

    res.json({ 
      success: true,
      valid: isValid,
      reason: isValid ? undefined : "Wrong answer",
      attempts: captchaData.attempts,
      difficulty: captchaData.difficulty
    });

  } catch (error) {
    console.error('CAPTCHA validation error:', error);
    res.status(500).json({ 
      success: false,
      valid: false, 
      reason: "Validation error" 
    });
  }
});

// Fallback CAPTCHA endpoint
app.get("/api/captcha/fallback", (req, res) => {
  try {
    const { reason, previousDifficulty, previousCaptchaId } = req.query;
    
    // Determine appropriate fallback difficulty
    let fallbackDifficulty = 'easy';
    const difficulties = ['extreme', 'hard', 'medium', 'easy'];
    
    if (previousDifficulty && difficulties.includes(previousDifficulty)) {
      const currentIndex = difficulties.indexOf(previousDifficulty);
      fallbackDifficulty = difficulties[Math.min(currentIndex + 1, difficulties.length - 1)];
    }
    
    // Clean up previous CAPTCHA if provided
    if (previousCaptchaId && captchaStore.has(previousCaptchaId)) {
      captchaStore.delete(previousCaptchaId);
    }
    
    // Redirect to main CAPTCHA endpoint with adjusted difficulty
    res.redirect(`/api/captcha?difficulty=${fallbackDifficulty}&fallback=true&reason=${encodeURIComponent(reason || 'unknown')}`);
    
  } catch (error) {
    console.error('Fallback CAPTCHA error:', error);
    res.redirect('/api/captcha?difficulty=easy');
  }
});

// Analytics endpoint
app.get("/api/analytics", (req, res) => {
  const now = Date.now();
  const activeCaptchas = Array.from(captchaStore.values());
  
  const stats = {
    timestamp: new Date().toISOString(),
    system: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      activeCaptchas: captchaStore.size
    },
    captchas: {
      byDifficulty: {},
      byType: {},
      validationAttempts: 0,
      successfulValidations: 0,
      failedValidations: 0
    },
    rateLimiting: {
      activeIPs: requestCounts.size
    }
  };
  
  // Calculate CAPTCHA statistics
  activeCaptchas.forEach(captcha => {
    // By difficulty
    stats.captchas.byDifficulty[captcha.difficulty] = 
      (stats.captchas.byDifficulty[captcha.difficulty] || 0) + 1;
    
    // By type
    stats.captchas.byType[captcha.type] = 
      (stats.captchas.byType[captcha.type] || 0) + 1;
    
    // Validation stats
    stats.captchas.validationAttempts += captcha.attempts;
    if (captcha.lastValidation) {
      if (captcha.lastValidation.valid) {
        stats.captchas.successfulValidations++;
      } else {
        stats.captchas.failedValidations++;
      }
    }
  });
  
  res.json({
    success: true,
    data: stats
  });
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: "1.0.0"
  });
});

// Service statistics
app.get("/api/stats", (req, res) => {
  res.json({
    success: true,
    data: {
      activeCaptchas: captchaStore.size,
      rateLimitedIPs: requestCounts.size,
      configuration: {
        captchaExpiration: `${config.captcha.expiration / 60000} minutes`,
        maxAttempts: config.captcha.maxAttempts,
        allowedDifficulties: config.security.allowedDifficulties
      }
    }
  });
});

// Demo page
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Voltura Captcha - Demo</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body { 
                font-family: 'Segoe UI', system-ui, sans-serif; 
                max-width: 800px; 
                margin: 0 auto; 
                padding: 20px; 
                background: #f5f5f5;
            }
            .header { 
                text-align: center; 
                margin-bottom: 40px; 
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .demo-container { 
                background: white; 
                padding: 30px; 
                border-radius: 12px; 
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .api-info { 
                background: #f8f9fa; 
                padding: 20px; 
                border-radius: 8px; 
                margin-top: 20px; 
            }
            .endpoint { 
                background: #e9ecef; 
                padding: 10px; 
                border-radius: 4px; 
                margin: 10px 0; 
                font-family: monospace; 
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Voltura Captcha System</h1>
            <p>Advanced bot protection with context-aware challenges</p>
        </div>
        
        <div class="demo-container">
            <h2>Live Demo</h2>
            <p>Try the CAPTCHA widget below:</p>
            <div id="captcha-widget"></div>
        </div>
        
        <div class="demo-container">
            <h2>API Endpoints</h2>
            <div class="api-info">
                <h3>Generate CAPTCHA</h3>
                <div class="endpoint">GET /api/captcha?difficulty=medium</div>
                
                <h3>Validate CAPTCHA</h3>
                <div class="endpoint">POST /api/validate-captcha</div>
                <pre>{ "captchaId": "uuid", "answer": "user-answer" }</pre>
                
                <h3>Fallback CAPTCHA</h3>
                <div class="endpoint">GET /api/captcha/fallback?reason=timeout</div>
                
                <h3>Analytics</h3>
                <div class="endpoint">GET /api/analytics</div>
                
                <h3>Health Check</h3>
                <div class="endpoint">GET /api/health</div>
            </div>
        </div>

        <script>
            // Simple demo integration
            fetch('/api/captcha')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('captcha-widget').innerHTML = \`
                            <div style="border: 2px solid #e2e8f0; padding: 20px; border-radius: 8px;">
                                <h3>Challenge: \${data.question}</h3>
                                <p><strong>Type:</strong> \${data.type} | <strong>Difficulty:</strong> \${data.difficulty}</p>
                                <p><small>CAPTCHA ID: \${data.captchaId}</small></p>
                            </div>
                        \`;
                    }
                });
        </script>
    </body>
    </html>
  `);
});

// Cleanup expired data
setInterval(() => {
  const now = Date.now();
  let expiredCount = 0;
  let attemptCount = 0;

  for (const [id, data] of captchaStore.entries()) {
    if (now > data.expiresAt) {
      captchaStore.delete(id);
      expiredCount++;
    }
    attemptCount += data.attempts;
  }

  // Clean rate limit data (keep last 24 hours only)
  const rateLimitCleanupWindow = 24 * 60 * 60 * 1000;
  for (const [key, requests] of requestCounts.entries()) {
    const validRequests = requests.filter(time => now - time < rateLimitCleanupWindow);
    if (validRequests.length === 0) {
      requestCounts.delete(key);
    } else {
      requestCounts.set(key, validRequests);
    }
  }

  if (expiredCount > 0 || attemptCount > 0) {
    console.log(`[Cleanup] Removed ${expiredCount} expired CAPTCHAs, tracked ${attemptCount} attempts`);
  }
}, config.captcha.cleanupInterval);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: "Internal server error",
    reference: uuid() // For support tracking
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
    path: req.path
  });
});

// Server startup
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║            Voltura Captcha Server            ║
║                 v1.0.0                       ║
║                                               ║
║   🚀 Server running on port ${PORT}           ║
║   📊 Analytics: /api/analytics               ║
║   ❤️  Health: /api/health                    ║
║   🔒 CAPTCHA: /api/captcha                   ║
║                                               ║
║   Environment: ${process.env.NODE_ENV || 'development'} ║
╚═══════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

export default app;
