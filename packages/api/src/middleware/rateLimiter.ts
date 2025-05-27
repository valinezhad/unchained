import { GraphQLError } from 'graphql';

interface RateLimitOptions {
  windowMs?: number; // Time window in milliseconds
  max?: number; // Max requests per window
  message?: string;
  keyGenerator?: (context: any) => Promise<string>;
}

type RateLimitStore = Record<
  string,
  {
    count: number;
    resetTime: number;
  }
>;

const stores: Record<string, RateLimitStore> = {};

// Clean up expired entries periodically
setInterval(() => {
  const now = Date.now();
  Object.keys(stores).forEach((storeName) => {
    const store = stores[storeName];
    Object.keys(store).forEach((key) => {
      if (store[key].resetTime < now) {
        delete store[key];
      }
    });
  });
}, 60000); // Clean every minute

// Helper to create hash using WebCrypto
async function createHash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const createRateLimiter = (storeName: string, options: RateLimitOptions = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes default
    max = 5, // 5 requests per window default
    message = 'Too many requests, please try again later.',
    keyGenerator = async (context) => {
      // Default key generator uses IP + userId
      const ip = context.req?.ip || context.req?.connection?.remoteAddress || 'unknown';
      const userId = context.userId || 'anonymous';
      return createHash(`${ip}-${userId}`);
    },
  } = options;

  // Initialize store for this limiter
  if (!stores[storeName]) {
    stores[storeName] = {};
  }
  const store = stores[storeName];

  return async (context: any) => {
    const key = await keyGenerator(context);
    const now = Date.now();

    // Get or create rate limit entry
    let entry = store[key];
    if (!entry || entry.resetTime < now) {
      entry = {
        count: 0,
        resetTime: now + windowMs,
      };
      store[key] = entry;
    }

    // Increment counter
    entry.count++;

    // Check if limit exceeded
    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
      throw new GraphQLError(message, {
        extensions: {
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter,
        },
      });
    }

    return true;
  };
};

// Pre-configured rate limiters for common use cases
export const authRateLimiter = createRateLimiter('auth', {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 minutes
  message: 'Too many authentication attempts. Please try again later.',
});

export const passwordResetRateLimiter = createRateLimiter('passwordReset', {
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  message: 'Too many password reset requests. Please try again later.',
  keyGenerator: async (context) => {
    // Rate limit by email/username instead of IP for password reset
    const { email, username } = context.args || {};
    const identifier = email || username || 'unknown';
    return createHash(identifier.toLowerCase());
  },
});

export const registrationRateLimiter = createRateLimiter('registration', {
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 registrations per hour per IP
  message: 'Too many registration attempts. Please try again later.',
  keyGenerator: async (context) => {
    // Rate limit by IP only for registrations
    const ip = context.req?.ip || context.req?.connection?.remoteAddress || 'unknown';
    return createHash(ip);
  },
});
