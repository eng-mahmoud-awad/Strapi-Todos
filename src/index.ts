import type { Core } from '@strapi/strapi';

export default {
  register(/* { strapi }: { strapi: Core.Strapi } */) {},

  bootstrap({ strapi }: { strapi: Core.Strapi }) {
    const authController = strapi.plugin('users-permissions').controller('auth');

    authController.register = async (ctx: any) => {
      const { username, email, password, firstname, lastname } = ctx.request.body;

      if (!username || !email || !password || !firstname || !lastname) {
        return ctx.badRequest('username, email, password, firstname and lastname are required');
      }

      const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });
      const settings = (await pluginStore.get({ key: 'advanced' })) as {
        allow_register: boolean;
        default_role: string;
        email_confirmation: boolean;
      };

      if (!settings.allow_register) {
        return ctx.badRequest('Register action is currently disabled');
      }

      const role = await strapi.db
        .query('plugin::users-permissions.role')
        .findOne({ where: { type: settings.default_role } });

      if (!role) {
        return ctx.badRequest('Impossible to find the default role');
      }

      const existingUser = await strapi.db
        .query('plugin::users-permissions.user')
        .findOne({ where: { email: email.toLowerCase() } });

      if (existingUser) {
        return ctx.badRequest('Email is already taken');
      }

      try {
        const newUser = await strapi
          .plugin('users-permissions')
          .service('user')
          .add({
            username,
            email: email.toLowerCase(),
            password,
            firstname,
            lastname,
            provider: 'local',
            role: role.id,
            confirmed: !settings.email_confirmation,
          });

        const sanitizedUser = await strapi
          .plugin('users-permissions')
          .service('user')
          .sanitizeOutput(newUser, ctx);

        if (settings.email_confirmation) {
          await strapi.plugin('users-permissions').service('user').sendConfirmationEmail(sanitizedUser);
          return ctx.send({ user: sanitizedUser });
        }

        const jwt = strapi.plugin('users-permissions').service('jwt').issue({ id: newUser.id });
        ctx.send({ jwt, user: sanitizedUser });
      } catch (err: any) {
        return ctx.badRequest(err.details?.errors?.[0]?.message || err.message);
      }
    };
  },
};