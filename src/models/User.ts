import { ObjectID } from 'mongodb';
import { Schema, Document, model as mongooseModel } from 'mongoose';
import { isEmail } from 'validator';
import * as bcrypt from 'bcryptjs';
import { pick } from 'lodash';
import { Account, AccountClaims, ClaimsParameterMember } from 'oidc-provider';

import { logger } from '../config/logger';

export interface IUser extends Document {
    username: string;
    first_name: string;
    last_name: string;
    full_name: string;
    birthdate: Date;
    profile_picture: string;
    email: string;
    email_verified: boolean;
    password: string;
    roles: [ObjectID];
    logins: [string];
}

var schema = new Schema({
    username: String,
    first_name: String,
    last_name: String,
    full_name: String,
    birthdate: Date,
    profile_picture: String,
    email: {
        type: String,
        required: true,
        minlength: 1,
        trim: true,
        unique: true,
        validate: {
            validator: isEmail
        }
    },
    email_verified: {
        type: Boolean,
        default: false
    },
    password: {
        type: String,
        require: true,
        minlength: 6
    },
    roles: [ObjectID],
    logins: [String]
})

schema.pre('save', function (next) {
    var user: any = this;

    if (user.isModified('password')) {
        bcrypt.genSalt(10, (err: Error, salt: string) => {
            bcrypt.hash(user.password, salt, (err: Error, hash: string) => {
                if (!err) {
                    user.password = hash;
                }
                next();
            });
        })
    } else {
        next();
    }
});

schema.virtual('accountId').get(function (this: { _id: string }) {
    return this._id;
});

schema.virtual('id').get(function (this: { _id: string }) {
    return this._id;
});

schema.methods.toJSON = function () {
    var user = this;
    var userObject = user.toObject();

    return pick(userObject, ['_id', 'email']);
};

// claims() should return or resolve with an object with claims that are mapped 1:1 to
// what your OP supports, oidc-provider will cherry-pick the requested ones automatically
schema.methods.claims = function () {
    return Object.assign({}, this._doc, {
        sub: this._id,
    });
}

export let UserSchema = mongooseModel<IUser>('User', schema);

// MODEL
export class UserModel {

    private _userModel: IUser;

    constructor(userModel: IUser) {
        this._userModel = userModel;
    }

    get id(): string {
        return this._userModel.id;
    }

    get firstname(): string {
        return this._userModel.first_name;
    }

    get lastname(): string {
        return this._userModel.last_name;
    }

    get fullname(): string {
        return this._userModel.full_name;
    }

    get email(): string {
        return this._userModel.email;
    }

    get birthdate(): Date {
        return this._userModel.birthdate;
    }

    get emailVerified(): boolean {
        return this._userModel.email_verified;
    }

    get password(): string {
        return this._userModel.email;
    }

    get roles(): [ObjectID] {
        return this._userModel.roles;
    }

    get logins(): [string] {
        return this._userModel.logins;
    }

    async claims(use: any, scope: string, claims: [string], rejected: any) {
        logger.debug('Claims', use, scope, claims, rejected)
        return Object.assign({}, this._userModel, {
            sub: this._userModel.id,
        });
    }

    static async createUser(email: string, password: string) {
        try {
            const userInstance = new UserSchema({ email, password });
            userInstance.save();
            return userInstance.toJSON();
        } catch (e) {
            throw new Error(e);
        }
    }

    static async findByID(ctx: any, id: string) {
        try {
            const user = await UserSchema.findById(id);
            return user;
        } catch (e) {
            throw new Error(e);
        }
    }

    static async findAccount(ctx: any, sub: string, token?: any): Promise<Account> {
        try {
            logger.debug('findAccount', sub);
            const user = await UserSchema.findById(sub);
            if (!user) throw new Error('User not found');
            const account: Account = {
                accountId: user.id,
                claims: (use: string, scope: string, claims: { [key: string]: ClaimsParameterMember | null; }, rejected: string[]) => {
                    const accountClaims: AccountClaims = {
                        sub: user.id
                    }
                    return accountClaims;
                }
            }
            return account;
        } catch (e) {
            throw new Error(e);
        }
    }

    static async findByCredentials(email: string, password: string) {
        try {
            const user = await UserSchema.findOne({ email });
            if (!user) {
                throw new Error('Credentials not valid');
            }
            const isvalid = await bcrypt.compare(password, user.password);
            if (!isvalid) {
                throw new Error('Credentials not valid');
            }
            return user;
        } catch (e) {
            throw new Error(e);
        }
    }

    static async findByLogin(login: string) {
        try {
            logger.debug('findByLogin', login);
            const users = await UserSchema.find({ email: 'test@test.com' })
            return users[0];
        } catch (e) {
            throw new Error(e);
        }
    }

}

Object.seal(UserModel);