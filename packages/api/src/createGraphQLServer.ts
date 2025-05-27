import { createLogger } from '@unchainedshop/logger';
import { createYoga, createSchema, YogaServerOptions } from 'graphql-yoga';
import { useInputValidation, InputValidationOptions } from './plugins/inputValidation.js';

const logger = createLogger('unchained:api');

export type GraphQLServerOptions = YogaServerOptions<any, any> & {
  typeDefs?: string[];
  resolvers?: Record<string, any>[];
  inputValidation?: InputValidationOptions | false;
};

export default async (options: GraphQLServerOptions) => {
  const {
    typeDefs,
    resolvers,
    schema: customSchema,
    inputValidation = {},
    plugins = [],
    ...graphQLServerOptions
  } = options || {};

  const schema =
    customSchema ||
    createSchema({
      typeDefs,
      resolvers,
    });

  // Build plugins array
  const allPlugins = [...plugins];

  // Add input validation plugin by default (unless explicitly disabled)
  if (inputValidation !== false) {
    allPlugins.push(useInputValidation(inputValidation));
  }

  const server = createYoga({
    schema,
    logging: logger,
    context: async (ctx: any) => {
      return (ctx.req as any)?.unchainedContext;
    },
    plugins: allPlugins,
    ...graphQLServerOptions,
  });

  return server;
};
