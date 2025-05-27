import { log } from '@unchainedshop/logger';
import { Context } from '../../../context.js';
import { passwordResetRateLimiter } from '../../../middleware/rateLimiter.js';

export default async function forgotPassword(
  root: never,
  { email }: { email: string },
  context: Context,
) {
  const { modules, userId } = context;

  // Apply rate limiting before any processing
  await passwordResetRateLimiter({ ...context, args: { email } });

  log('mutation forgotPassword', { email, userId });

  // Always return success to prevent email enumeration
  const user = await modules.users.findUserByEmail(email);

  if (user) {
    // Only send email if user exists, but don't reveal this
    try {
      await modules.users.sendResetPasswordEmail(user._id, email);
    } catch (error) {
      // Log error but don't expose it
      log('Failed to send reset password email', { email, error });
    }
  }

  // Always return success to prevent email enumeration
  return {
    success: true,
  };
}
