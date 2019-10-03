
const MONGODB_SERVER = '127.0.0.1:27017'
const DB_NAME = 'oidc';

const DB_URI = (server: string, dbname: string) => `mongodb://${MONGODB_SERVER}/${dbname}`;

export {
    DB_URI,
    DB_NAME,
    MONGODB_SERVER
};