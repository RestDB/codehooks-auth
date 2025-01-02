import { app, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import handlebars from 'handlebars';

export interface AuthStrategy {
    settings: any,
    onSignupUser: (req: httpRequest, res: httpResponse, payload: any) => Promise<any>,
    onLoginUser: (req: httpRequest, res: httpResponse, payload: any) => Promise<any>,
    sendOTPMail: (content: Object) => Promise<any>,
    initialize: (cohoApp: typeof app, settings: any, onSignupUser: (req: httpRequest, res: httpResponse, payload: any) => Promise<any>, onLoginUser: (req: httpRequest, res: httpResponse, payload: any) => Promise<any>, sendMail: (content: Object) => Promise<any>) => void;
    login: (req: httpRequest, res: httpResponse) => Promise<void>;
    signup?: (req: httpRequest, res: httpResponse) => Promise<void>;
    verify?: (req: httpRequest, res: httpResponse) => Promise<void>;
    callback?: (req: httpRequest, res: httpResponse, next?: nextFunction) => Promise<void>;
}

export type AuthSettings = {
    userCollection?: string,
    saltRounds?: number,
    JWT_ACCESS_TOKEN_SECRET: string,
    JWT_ACCESS_TOKEN_SECRET_EXPIRE?: string,
    JWT_REFRESH_TOKEN_SECRET:string,
    JWT_REFRESH_TOKEN_SECRET_EXPIRE?: string,
    baseUrl: string,
    redirectSuccessUrl?: string,
    redirectFailUrl?: string,
    useCookie?: boolean,
    baseAPIRoutes?: string,
    defaultUserActive?: boolean,
    google?: {
        CLIENT_ID: string,
        CLIENT_SECRET: string,
        REDIRECT_URI?: string,
        SCOPE?: string | string[]
    },
    github?: {
        CLIENT_ID: string,
        CLIENT_SECRET: string,
        REDIRECT_URI?: string,
        SCOPE?: string | string[]
    },
    emailProvider: 'mailgun' | 'postmark' | 'sendgrid' | 'none',
    emailSettings?: {
        mailgun?: {
            MAILGUN_APIKEY: string,
            MAILGUN_DOMAIN: string,
            MAILGUN_FROM_EMAIL: string,
            MAILGUN_FROM_NAME: string
        },
        sendgrid?: {
            SENDGRID_APIKEY: string,
            SENDGRID_FROM_EMAIL: string,
            SENDGRID_FROM_NAME: string
        },
        postmark?: {
            POSTMARK_APIKEY: string,
            POSTMARK_FROM_EMAIL: string,
            POSTMARK_FROM_NAME: string
        }
    },
    emailSignupData?: {
        subject: string,
        title: string,
        productName: string,
        productUrl: string,
        companyName: string,
        companyAddress: string,
        companySuite: string,
        support_email: string,
        live_chat_url: string,
        help_url: string,
        login_url: string,
        senderName: string
    },
    emailOTPData?: {
        subject: string,
        title: string,
        productName: string,
        productUrl: string,
        companyName: string,
        companyAddress: string,
        companySuite: string,
        support_email: string,
        live_chat_url: string,
        help_url: string,
        login_url: string,
        senderName: string
    },
    labels?: {
        signinTitle?: string,
        signupTitle?: string,
        forgotTitle?: string,
        otpTitle?: string
    },
    templateLoaders?: {
        layout?: () => Function;
        login?: () => Function;
        otp?: () => Function;
        signup?: () => Function;
        emailTemplateWelcome?: () => Function;
        emailTemplateWelcomeText?: () => Function;
        emailTemplateOTP?: () => Function;
        emailTemplateOTPText?: () => Function;
    },
    onLoginUser?: (req:httpRequest, res:httpResponse, payload: any) => void,
    onSignupUser?: (req:httpRequest, res:httpResponse, payload: any) => void
}