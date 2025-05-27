import { Plugin } from 'graphql-yoga';
import { GraphQLError } from 'graphql';

// Dangerous patterns to check for
const DANGEROUS_PATTERNS = [
  /<script/i, // Script tags
  /<iframe/i, // Iframes
  /<object/i, // Object embeds
  /<embed/i, // Embed tags
  /<link/i, // Link tags (can load CSS)
  /javascript:/i, // JavaScript protocol
  /vbscript:/i, // VBScript protocol
  /on\w+\s*=/i, // Event handlers (onclick, onload, etc)
  /<meta/i, // Meta tags
  /data:text\/html/i, // Data URLs with HTML
  /<svg.*onload/i, // SVG with event handlers
  /&#x?[0-9a-f]+;/i, // HTML entities (could be obfuscation)
  /\\u[0-9a-f]{4}/i, // Unicode escapes
  /expression\s*\(/i, // CSS expressions
  /@import/i, // CSS imports
  /<!--|-->/, // HTML comments
];

function checkForDangerousContent(value: string, path: string): void {
  for (const dangerous of DANGEROUS_PATTERNS) {
    if (dangerous.test(value)) {
      throw new GraphQLError(`Potentially dangerous content detected in ${path}`, {
        extensions: {
          code: 'DANGEROUS_INPUT',
          path,
        },
      });
    }
  }
}

function validateValue(value: any, path = ''): any {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    checkForDangerousContent(value, path);
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => validateValue(item, `${path}[${index}]`));
  }

  if (typeof value === 'object') {
    const validated: any = {};
    for (const [key, val] of Object.entries(value)) {
      validated[key] = validateValue(val, path ? `${path}.${key}` : key);
    }
    return validated;
  }

  return value;
}

export interface InputValidationOptions {
  // Skip validation for specific operations
  skipOperations?: string[];
  // Skip validation for specific fields
  skipFields?: string[];
  // Custom validation function
  customValidator?: (value: any, path: string) => void;
  // Whether to log validation errors
  logErrors?: boolean;
}

export function useInputValidation(options: InputValidationOptions = {}): Plugin {
  const { skipOperations = [], skipFields = [], customValidator, logErrors = false } = options;

  return {
    onParams({ params, setParams }) {
      // Get operation name from the request
      const operationName = params.operationName || '';

      // Skip if operation is in skip list
      if (operationName && skipOperations.includes(operationName)) {
        return;
      }

      try {
        // Validate variables
        if (params.variables) {
          const validatedVariables: any = {};

          for (const [key, value] of Object.entries(params.variables)) {
            if (!skipFields.includes(key)) {
              validatedVariables[key] = validateValue(value, `variables.${key}`);

              // Run custom validator if provided
              if (customValidator) {
                customValidator(value, `variables.${key}`);
              }
            } else {
              validatedVariables[key] = value;
            }
          }

          // Update params with validated variables
          setParams({
            ...params,
            variables: validatedVariables,
          });
        }
      } catch (error) {
        if (logErrors) {
          console.error('Input validation error:', error);
        }
        throw error;
      }
    },
  };
}
