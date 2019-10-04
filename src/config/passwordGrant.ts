import { Provider } from 'oidc-provider';
import { UserModel, IUser } from '../models/User';

const gty = 'password';
const scope = 'openid';

// This is very ugly and should never be used, will be removed later
const passwordGrant = (provider: Provider) => {

    const parameters = ['username', 'password'];

    provider.registerGrantType('password', async (ctx, next: any) => {

        if (!ctx.oidc.params) {
            ctx.body = {
                error: 'invalid_grant',
                error_description: 'invalid params provided',
            };
            ctx.status = 400;
            await next();
            return;
        }

        let identity: IUser;
        if ((identity = await UserModel.findByCredentials(ctx.oidc.params.username, ctx.oidc.params.password))) {

            const {
                AccessToken, IdToken, RefreshToken, ReplayDetection,
            } = ctx.oidc.provider;

            if (!ctx.oidc.client) {
                ctx.body = {
                    error: 'invalid_grant',
                    error_description: 'invalid client provided',
                };
                ctx.status = 400;
                await next();
                return;
            }

            const at = new AccessToken({
                accountId: identity.id,
                email: identity.email,
                client: ctx.oidc.client,
                grantId: ctx.oidc.uid,
                gty,
                scope
            });

            const rt = new RefreshToken({
                accountId: identity.id,
                client: ctx.oidc.client,
                grantId: ctx.oidc.uid,
                gty,
                rotations: 0,
                scope
            });

            const accessToken = await at.save();
            const refreshToken = await rt.save();

            ctx.body = {
                access_token: accessToken,
                expires_in: at.expiration,
                refresh_token: refreshToken,
                scope,
                token_type: at.tokenType,
            };

        } else {
            ctx.body = {
                error: 'invalid_grant',
                error_description: 'invalid credentials provided',
            };
            ctx.status = 400;
        }

        await next();
    }, parameters);

}

export default passwordGrant;