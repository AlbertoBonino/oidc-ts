// DEPENDENCIES
import * as path from 'path';
import * as url from 'url';
import { set } from 'lodash';
import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { Provider } from 'oidc-provider';
import { Server } from 'http';

// LOCAL IMPORTS
import { logger, expressLogger } from './config/logger';
import { DB_NAME, DB_URI, MONGODB_SERVER } from './config/constants';
import MongoAdapter from './adapter/mongodb';
import MongooseHelper from './db/mongoose.helper';
import { UserSchema, UserModel } from './models/User';
import interactionsRoutes from './routes/interactionsRoutes';
import passwordGrant from './config/passwordGrant';

import oidcConfig from './config/oidc-config';

const { PORT = 3000, ISSUER = `http://localhost:${PORT}` } = process.env;

// MONGOOSE CONNECT
MongooseHelper.connect(DB_URI(MONGODB_SERVER, DB_NAME));

// EXPRESS CONFIG
const app: Application = express();
app.use(helmet());
// app.use(expressLogger);

// Views setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// EXPRESS ROUTES
app.get('/isalive', (req: Request, res: Response) => {
    res.send('Server is alive');
});

// SERVER & OIDC setup
let server: Server;
(async () => {

    const provider = new Provider(ISSUER, { adapter: MongoAdapter, ...oidcConfig });
    passwordGrant(provider);

    if (process.env.NODE_ENV === 'production') {

        logger.debug('Production');

        app.enable('trust proxy');
        provider.proxy = true;
        set(oidcConfig, 'cookies.short.secure', true);
        set(oidcConfig, 'cookies.long.secure', true);

        app.use((req, res, next) => {
            if (req.secure) {
                next();
            } else if (req.method === 'GET' || req.method === 'HEAD') {
                res.redirect(url.format({
                    protocol: 'https',
                    host: req.get('host'),
                    pathname: req.originalUrl,
                }));
            } else {
                res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'do yourself a favor and only use https',
                });
            }
        });
    }

    interactionsRoutes(app, provider);
    app.use(provider.callback);

    server = app.listen(PORT, () => {
        logger.info(`OIDC app is listening on port ${PORT}, check its /.well-known/openid-configuration`);
    });

})().catch((err) => {
    if (server && server.listening) server.close();
    logger.error(err);
    process.exitCode = 1;
});