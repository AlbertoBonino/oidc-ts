import { connect as mongoConnect, Mongoose } from 'mongoose';

export default class MongooseHelper {

    private static client: Mongoose;

    constructor() {
    }

    public static connect(uri: string) {
        if (!MongooseHelper.client) {
            mongoConnect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
                .then((conn) => {
                    console.log('Mongoose conn ok')
                    MongooseHelper.client = conn;
                })
                .catch(err => {
                    console.error('Mongoose conn error')
                })
        } else {
            return MongooseHelper.client;
        }
    }

    // public static disconnect(): void {
    //     if (!MongooseHelper.client) {
    //         MongooseHelper.client.disconnect();
    //         MongooseHelper.client = null;
    //     }
    // }
}