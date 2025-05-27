import { GraphQLError } from 'graphql';

interface LoginAttempt {
  count: number;
  firstAttempt: number;
  lastAttempt: number;
  lockedUntil?: number;
}

// Store login attempts by user identifier (username/email)
const loginAttempts = new Map<string, LoginAttempt>();

// Configuration
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes
const ATTEMPT_WINDOW = 15 * 60 * 1000; // 15 minutes

// Clean up old entries periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [key, attempt] of loginAttempts.entries()) {
      // Remove entries older than 24 hours
      if (now - attempt.lastAttempt > 24 * 60 * 60 * 1000) {
        loginAttempts.delete(key);
      }
    }
  },
  60 * 60 * 1000,
); // Clean every hour

async function createIdentifierHash(identifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(identifier.toLowerCase());
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function checkAccountLockout(identifier: string): Promise<void> {
  const hashedIdentifier = await createIdentifierHash(identifier);
  const attempt = loginAttempts.get(hashedIdentifier);

  if (!attempt) return;

  const now = Date.now();

  // Check if account is locked
  if (attempt.lockedUntil && attempt.lockedUntil > now) {
    const remainingMinutes = Math.ceil((attempt.lockedUntil - now) / 60000);
    throw new GraphQLError(`Account is locked. Please try again in ${remainingMinutes} minutes.`, {
      extensions: {
        code: 'ACCOUNT_LOCKED',
        lockedUntil: attempt.lockedUntil,
        remainingMinutes,
      },
    });
  }

  // Reset attempts if outside the window
  if (now - attempt.firstAttempt > ATTEMPT_WINDOW) {
    loginAttempts.delete(hashedIdentifier);
  }
}

export async function recordFailedLoginAttempt(identifier: string): Promise<void> {
  const hashedIdentifier = await createIdentifierHash(identifier);
  const now = Date.now();

  let attempt = loginAttempts.get(hashedIdentifier);

  if (!attempt || now - attempt.firstAttempt > ATTEMPT_WINDOW) {
    // Create new attempt record or reset if outside window
    attempt = {
      count: 1,
      firstAttempt: now,
      lastAttempt: now,
    };
  } else {
    // Increment existing attempt
    attempt.count++;
    attempt.lastAttempt = now;

    // Lock account if max attempts exceeded
    if (attempt.count >= MAX_ATTEMPTS) {
      attempt.lockedUntil = now + LOCKOUT_DURATION;
    }
  }

  loginAttempts.set(hashedIdentifier, attempt);

  // Provide warning about remaining attempts
  if (attempt.count >= 3 && attempt.count < MAX_ATTEMPTS) {
    const remainingAttempts = MAX_ATTEMPTS - attempt.count;
    throw new GraphQLError(
      `Invalid credentials. ${remainingAttempts} attempts remaining before account lockout.`,
      {
        extensions: {
          code: 'INVALID_CREDENTIALS',
          remainingAttempts,
        },
      },
    );
  }
}

export async function clearLoginAttempts(identifier: string): Promise<void> {
  const hashedIdentifier = await createIdentifierHash(identifier);
  loginAttempts.delete(hashedIdentifier);
}
