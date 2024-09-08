import { app, httpRequest, httpResponse, nextFunction } from 'codehooks-js';

export interface AuthStrategy {
    settings: any,
    initialize: (cohoApp: typeof app, settings: any) => void;
    login: (req: httpRequest, res: httpResponse) => Promise<void>;
    callback?: (req: httpRequest, res: httpResponse, next?: nextFunction) => Promise<void>;
}

export type AuthSettings = {
    userCollection?: string,
    saltRounds?: number,
    JWT_ACCESS_TOKEN_SECRET: string,
    JWT_ACCESS_TOKEN_SECRET_EXPIRE: string,
    JWT_REFRESH_TOKEN_SECRET:string,
    JWT_REFRESH_TOKEN_SECRET_EXPIRE:string,
    redirectSuccessUrl?: string,
    redirectFailUrl?: string,
    useCookie?: boolean,
    baseAPIRoutes?: string,
    google?: {
        CLIENT_ID: string,
        CLIENT_SECRET: string,
        REDIRECT_URI?: string,
        SCOPE?: string | string[]
    },
    onAuthUser?: (req:httpRequest, res:httpResponse, payload: any) => void
}
