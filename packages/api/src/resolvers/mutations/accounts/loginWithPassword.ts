import { log } from '@unchainedshop/logger';
import { InvalidCredentialsError, UsernameOrEmailRequiredError } from '../../../errors.js';
import { Context } from '../../../context.js';
import { authRateLimiter } from '../../../middleware/rateLimiter.js';
import {
  checkAccountLockout,
  recordFailedLoginAttempt,
  clearLoginAttempts,
} from '../../../middleware/accountLockout.js';

export default async function loginWithPassword(
  root: never,
  params: {
    username?: string;
    email?: string;
    password: string;
  },
  context: Context,
) {
  const { username, email, password } = params;

  // Apply rate limiting
  await authRateLimiter({ ...context, args: params });

  log('mutation loginWithPassword', { username, email });

  if (!username && !email) throw new UsernameOrEmailRequiredError({});

  const identifier = username || email;

  // Check if account is locked
  await checkAccountLockout(identifier);

  let user = username
    ? await context.modules.users.findUserByUsername(username)
    : await context.modules.users.findUserByEmail(email);

  if (!user) {
    await recordFailedLoginAttempt(identifier);
    throw new InvalidCredentialsError({ username, email });
  }

  const verified =
    user.services?.password &&
    (await context.modules.users.verifyPassword(user.services.password, password));

  if (!verified) {
    await recordFailedLoginAttempt(identifier);
    throw new InvalidCredentialsError({ username, email });
  }

  // Clear login attempts on successful login
  await clearLoginAttempts(identifier);

  if (user.guest) {
    await context.modules.users.updateGuest(user, false);
  }

  user = await context.modules.users.updateHeartbeat(user._id, {
    remoteAddress: context.remoteAddress,
    remotePort: context.remotePort,
    userAgent: context.getHeader('user-agent'),
    locale: context.locale.baseName,
    countryCode: context.countryCode,
  });

  if (context.userId) {
    await context.services.users.migrateUserData(context.userId, user._id);
  }

  await context.services.orders.nextUserCart({ user, countryCode: context.countryCode });

  return context.login(user);
}
