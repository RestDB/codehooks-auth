import { AuthSettings } from './types';
import { passwordAuth } from './strategies/passwordAuth';
import { googleAuth } from './strategies/googleAuth';
import { githubAuth } from './strategies/githubAuth';
import { otpAuth } from './strategies/otpAuth';
import handlebars from 'handlebars';
import { app, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { getJwtForAccessToken, refreshAccessToken, verifyAccessToken, setAuthCookies } from './lib';
import * as jwt from 'jsonwebtoken';
import ms from 'ms';
import * as cookie from 'cookie';
import { randomBytes } from 'crypto';
import { sendMail as mailgun } from './strategies/mailgun';
import fetch from 'node-fetch';

// Handlebars templates
const layoutHbs = require('./auth/assets/layout.hbs');
const loginHbs = require('./auth/assets/login.hbs');
const otpHbs = require('./auth/assets/otp.hbs');
const signupHbs = require('./auth/assets/signup.hbs');
const emailTemplateWelcomeHbs = require('./auth/assets/emailTemplateWelcome.hbs');
const emailTemplateWelcomeTextHbs = require('./auth/assets/emailTemplateWelcomeText.hbs');
const emailTemplateOTPHbs = require('./auth/assets/emailTemplateOTP.hbs');
const emailTemplateOTPTextHbs = require('./auth/assets/emailTemplateOTPText.hbs');
const layoutTemplate = handlebars.compile(layoutHbs);
const loginTemplate = handlebars.compile(loginHbs);
const otpTemplate = handlebars.compile(otpHbs);
const signupTemplate = handlebars.compile(signupHbs);
const emailTemplateWelcome = handlebars.compile(emailTemplateWelcomeHbs);
const emailTemplateWelcomeText = handlebars.compile(emailTemplateWelcomeTextHbs);
const emailTemplateOTP = handlebars.compile(emailTemplateOTPHbs);
const emailTemplateOTPText = handlebars.compile(emailTemplateOTPTextHbs);

// TODO: add Microsoft auth
const strategies = {
    password: passwordAuth,
    google: googleAuth,
    github: githubAuth,
    otp: otpAuth
  };

// Default settings
let settings: AuthSettings = {
    baseUrl: 'http://localhost:3000',
    userCollection: 'users', //database collection for users
    saltRounds: 10, // Number of salt rounds for hashing
    JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET || randomBytes(32).toString('hex'),
    JWT_ACCESS_TOKEN_SECRET_EXPIRE: '15m',
    JWT_REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET || randomBytes(32).toString('hex'),
    JWT_REFRESH_TOKEN_SECRET_EXPIRE: '8d',
    redirectSuccessUrl: '/',
    redirectFailUrl: '/',
    useCookie: true,
    baseAPIRoutes: '/',
    defaultUserActive: false,
    labels: {
        signinTitle: 'Sign in',
        signupTitle: 'Sign up',
        forgotTitle: 'Forgot password',
        otpTitle: 'OTP'
    },
    emailProvider: 'none',
    emailSignupData: {
        subject: 'Welcome to Example',
        title: 'Welcome to Example',
        productName: 'Example',
        productUrl: 'https://example.com',
        companyName: 'Example',
        companyAddress: '123 Main St, Anytown, USA',
        companySuite: '12345',
        support_email: 'support@example.com',
        live_chat_url: 'https://example.com/livechat',
        help_url: 'https://example.com/help',
        login_url: 'https://example.com/login',
        senderName: 'Jones, Example'
    },
    emailOTPData: {
        subject: 'One-Time Password',
        title: 'One-Time Password',
        productName: 'Example',
        productUrl: 'https://example.com',
        companyName: 'Example',
        companyAddress: '123 Main St, Anytown, USA',
        companySuite: '12345',
        support_email: 'support@example.com',
        live_chat_url: 'https://example.com/livechat',
        help_url: 'https://example.com/help',
        login_url: 'https://example.com/login',
        senderName: 'Jones, Example'
    },
    templateLoaders: {
        layout: () => {return handlebars.compile(require('./auth/assets/layout.hbs'))},
        login: () => {return handlebars.compile(require('./auth/assets/login.hbs'))},
        otp: () => {return handlebars.compile(require('./auth/assets/otp.hbs'))},
        signup: () => {return handlebars.compile(require('./auth/assets/signup.hbs'))},
        emailTemplateWelcome: () => {return handlebars.compile(require('./auth/assets/emailTemplateWelcome.hbs'))},
        emailTemplateWelcomeText: () => {return handlebars.compile(require('./auth/assets/emailTemplateWelcomeText.hbs'))},
        emailTemplateOTP: () => {return handlebars.compile(require('./auth/assets/emailTemplateOTP.hbs'))},
        emailTemplateOTPText: () => {return handlebars.compile(require('./auth/assets/emailTemplateOTPText.hbs'))}
    }
}

// Export the AuthSettings type that's being imported
export { AuthSettings } from './types';


// Initialize authentication for a Codehooks app
export function initAuth(cohoApp: typeof app, appSettings?: AuthSettings, callback?: (req:httpRequest, res:httpResponse, payload: any)=>void) {
    try {
        // merge settings        
        if (appSettings.labels) {
            settings.labels = { ...settings.labels, ...appSettings.labels };
        }
        // merge template loaders
        if (appSettings.templateLoaders) {
            // Preserve existing template loader functions if not overridden
            for (const key in appSettings.templateLoaders) {
                settings.templateLoaders[key] = appSettings.templateLoaders[key];
            }            
        }
        delete appSettings.templateLoaders;

        settings = { ...settings, ...appSettings };        
                
        
        if (callback) {
            settings.onLoginUser = callback;
        }
        
        // Initialize strategies
        try {
            Object.values(strategies).forEach(strategy => strategy.initialize(cohoApp, settings, onSignupUser, onLoginUser, sendOTPMail));
        } catch (error) {
            console.error('Error initializing strategies', error)
        }
                
        
        // allow public access to login api
        cohoApp.auth('/auth/*', (req, res, next) => {
            next()
        })
        
        // route to get jwt from access token
        cohoApp.auth('/auth/accesstoken', (req, res, next) => {next()})   
        cohoApp.post('/auth/accesstoken', (req, res) => getJwtForAccessToken(req, res, Datastore))   
        
        // route to refresh access token
        cohoApp.auth('/auth/refreshtoken', (req, res, next) => {next()})   
        cohoApp.post('/auth/refreshtoken', (req, res) => refreshAccessToken(req, res, settings))
        
        // protect this API with a JWT
        cohoApp.auth(`${settings.baseAPIRoutes}/*`, verifyAccessToken(settings))
        
        // serve lock screens
        cohoApp.get('/auth/login', async (req: httpRequest, res: httpResponse) =>{
            console.debug('app settings', settings.templateLoaders)
            // Add property name logging
            Object.keys(settings.templateLoaders).forEach(key => {
                console.debug(`Template loader: ${key}`);
            });
            const hasSocial = settings.github || settings.google;
            const body = settings.templateLoaders.login()({
                signinTitle: settings.labels.signinTitle,
                hasSocial,
                hasGoogle: settings.google,
                hasGithub: settings.github
            })
            res.send(settings.templateLoaders.layout()({
                contentBlock: body, 
                script: 'signin.js'
            }))
                         
        })
        // signup template
        cohoApp.get('/auth/signup', async (req: httpRequest, res: httpResponse) =>{
            const hasSocial = settings.github || settings.google;
            const body = settings.templateLoaders.signup()({
                signupTitle: settings.labels.signupTitle,
                hasSocial,
                hasGoogle: settings.google,
                hasGithub: settings.github
            })
            res.send(settings.templateLoaders.layout()({
                contentBlock: body, 
                script: 'signin.js'
            }))
        })
        // forgot password template
        cohoApp.get('/auth/forgot', async (req: httpRequest, res: httpResponse) =>{
            console.debug('forgot template')
            res.end('Not implemented')
        })
        // otp template
        cohoApp.get('/auth/otp', async (req: httpRequest, res: httpResponse) =>{
            console.debug('otp template')
            const body = settings.templateLoaders.otp()({
                otpTitle: settings.labels.otpTitle
            })
            res.send(settings.templateLoaders.layout()({
                contentBlock: body, 
                script: 'otp.js'
            }))
        })
        
        // logout user
        cohoApp.get('/auth/logout', logoutUser)

        // activate account
        cohoApp.get('/auth/activate/:token', activateAccount)
        
        // serve static assets
        cohoApp.static({ route: '/auth', directory: '/auth/assets' })
        
        return 'OK'
    } catch (error) {
        console.error('initAuth', error)
        return 'Error initializing auth'
    }
}

// activate account
async function activateAccount(req: httpRequest, res: httpResponse) {
    try {
        const db = await Datastore.open();
        const { token } = req.params;
        const email = await db.get(`activate:${token}`);
        console.debug('activateAccount', token, email)
        if (!email) {
            res.redirect(302, settings.redirectFailUrl);
            return;
        }
        
        const aUser = await db.getOne(settings.userCollection, { email });
        if (aUser) {
            const newToken = jwt.sign({ email, id: aUser._id }, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            const refreshToken = jwt.sign({ email, id: aUser._id }, settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            setAuthCookies(res, newToken, refreshToken, settings);        
            await db.updateOne(settings.userCollection, { email: aUser.email }, { $set: { active: true } });
            res.redirect(302, `${settings.redirectSuccessUrl}#access_token=${newToken}&login=true`);
        } else {
            res.redirect(302, settings.redirectFailUrl);
        }
    } catch (error) {
        console.error('activateAccount', error);
        res.redirect(302, settings.redirectFailUrl);
    }
}

// TODO: add mail strategy
async function sendOTPMail(content: Object): Promise<any> {
    return new Promise(async (resolve, reject) => {
        try {
            console.debug('sendMail', content);
            const emailData = {
                productName: settings.emailOTPData.productName,
                productUrl: settings.emailOTPData.productUrl,
                name: content['name'] || content['to'],
                otp: content['otp'],
                action_text: 'Login',
                action_url: `${settings.baseUrl}/auth/otp/verify?otp=${content['otp']}&email=${content['to']}`,
                companyName: settings.emailOTPData.companyName,
                companyAddress: settings.emailOTPData.companyAddress,
                companySuite: settings.emailOTPData.companySuite,
                support_email: settings.emailOTPData.support_email,
                live_chat_url: settings.emailOTPData.live_chat_url,
                help_url: settings.emailOTPData.help_url,
                login_url: `${settings.baseUrl}/auth/login`,
                username: content['to'],
                subject: settings.emailOTPData.subject,
                to: content['to'],
                title: settings.emailOTPData.title,
                senderName: settings.emailOTPData.senderName,
            }
            const html = settings.templateLoaders.emailTemplateOTP()(emailData)
            const text = settings.templateLoaders.emailTemplateOTPText()(emailData)
            // Select email provider and settings based on configuration
            const emailProvider = settings.emailProvider || 'none';            
            
            switch (emailProvider.toLowerCase()) {
                case 'none':
                    console.debug('No email provider selected');
                    reject({message: 'No email provider selected'});
                    break;
                case 'mailgun':
                    
                    const subject = emailData.subject;
                    const to = emailData.to;
                    console.debug('Sending email to', to, html, text, subject)
                    const mgresult = await mailgun(settings.emailSettings.mailgun,{text, html, subject, to});
                    resolve({message: 'Email sent', mgresult});
                    break;
                case 'postmark':
                    const pmresult = await sendMailPostmark(settings.emailSettings.postmark, {
                        to: emailData.to,
                        subject: emailData.subject,
                        text,
                        html
                    });
                    resolve({message: 'Email sent', pmresult});
                    break;
                // Add other email providers here
                // case 'sendgrid':
                //     from = settings.emailSettings?.sendgrid?.SENDGRID_FROM_EMAIL;
                //     return sendgrid({...content, from}).then(resolve).catch(reject);
                
                default:
                    throw new Error(`Unsupported email provider: ${emailProvider}`);
            }
        } catch (error) {
            console.error('sendMail', error);
            reject(error);
        }
    });    
}

async function sendMailPostmark(settings: any, emailData: any): Promise<any> {
    try {
        const response = await fetch("https://api.postmarkapp.com/email", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Postmark-Server-Token": settings.POSTMARK_APIKEY,
            },
            body: JSON.stringify({
                From: settings.POSTMARK_FROM_EMAIL,
                To: emailData.to,
                Subject: emailData.subject,
                TextBody: emailData.text,
                HtmlBody: emailData.html,
            }),
        });
    
        if (response.ok) {
            const result = await response.json();
            console.debug("Email sent successfully:", result);
            return { message: 'Email sent', result };
        } else {
            const error = await response.json();
            console.error("Failed to send email:", error);
            throw { message: 'Failed to send email', error };
        }
    } catch (error) {
        console.error("Error sending email:", error.message);
        throw { message: 'Failed to send email', error };
    }
}

// Called after successful signup strategy
async function onSignupUser(req: httpRequest, res: httpResponse, payload: any) {
    return new Promise(async (resolve, reject) => {
        const db = await Datastore.open();
        let signupData = null;
        const activationToken = randomBytes(32).toString('hex')
        console.debug('onSignupUser', payload, activationToken)
        await db.set(`activate:${activationToken}`, payload.email, { ttl: 60 * 1000 * 60 }); // 60 minutes
        if (payload.otp) {
            await db.set(`activate-otp:${payload.email}`, payload.otp, { ttl: 60 * 1000 * 60 }); // 60 minutes
        }
        
        // user does not exist, create new user
        signupData = await db.updateOne(settings.userCollection, {email: payload.email}, {$set: {active: settings.defaultUserActive, email: payload.email, firstLogin: new Date().toISOString(), ...payload}}, {upsert: true})
        console.debug('signupData', signupData)
        const token = jwt.sign({ email: payload.email, id: signupData._id }, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
        const refreshToken = jwt.sign({ email: payload.email, id: signupData._id }, settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
        if (settings.onSignupUser) {
            settings.onSignupUser(req, res, {access_token: token, user: signupData})
        } 
        if (settings.useCookie) {
            setAuthCookies(res, token, refreshToken, settings);
        }
        const emailData = {
            subject: settings.emailSignupData.subject,
            to: payload.email,
            title: settings.emailSignupData.title,
            productName: settings.emailSignupData.productName,
            productUrl: settings.emailSignupData.productUrl,
            name: signupData.name || signupData.email,
            action_text: 'Confirm email and activate your account',
            action_url: `${settings.baseUrl}/auth/activate/${activationToken}`,
            companyName: settings.emailSignupData.companyName,
            companyAddress: settings.emailSignupData.companyAddress,
            companySuite: settings.emailSignupData.companySuite,
            support_email: settings.emailSignupData.support_email,
            live_chat_url: settings.emailSignupData.live_chat_url,
            help_url: settings.emailSignupData.help_url,
            login_url: `${settings.baseUrl}/auth/login`,
            username: signupData.email,            
            senderName: settings.emailSignupData.senderName,
            otp: payload.otp || null
        }
        const html = settings.templateLoaders.emailTemplateWelcome()(emailData)
        const text = settings.templateLoaders.emailTemplateWelcomeText()(emailData)
        const subject = emailData.subject;
        const to = emailData.to;
        
        const emailProvider = settings.emailProvider || 'none';            
        console.debug('Sending signup email', emailProvider)
            
        switch (emailProvider.toLowerCase()) {
            case 'none':
                console.debug('No email provider selected');
                reject({message: 'No email provider selected'});
                break;
            case 'mailgun':
                await mailgun(settings.emailSettings.mailgun,{text, html, subject, to});
                break;
            case 'postmark':
                await sendMailPostmark(settings.emailSettings.postmark, {text, html, subject, to});
                break;
            default:
                throw new Error(`Unsupported email provider: ${emailProvider}`);
        }
        resolve({ token, refreshToken })
    })  
}

// Called after successful login strategy
async function onLoginUser(req: httpRequest, res: httpResponse, payload: any) {
    return new Promise(async (resolve, reject) => { 
        const db = await Datastore.open();
        try {
            const aUser = await db.getOne(settings.userCollection, { email: payload.email })
            const token = jwt.sign({ email: aUser.email, id: aUser._id }, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            const refreshToken = jwt.sign({ email: aUser.email, id: aUser._id }, settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            if (settings.onLoginUser) {
                try {
                    settings.onLoginUser(req, res, {access_token: token, user: aUser})
                } catch (error) {
                    console.error('Error in onLoginUser override', error)
                    reject({error: error.message})
                }
            } 
            if (settings.useCookie) {
                setAuthCookies(res, token, refreshToken, settings);
            }
            await db.updateOne(settings.userCollection, { email: payload.email }, { $set: { lastLogin: new Date().toISOString(), ...payload }, $inc: { "success": 1 } })              
            resolve({ token, refreshToken })
        } catch (error) {
            console.error('Error in onLoginUser', error)
            reject({error: error.message})
        }
    })
}

// logout user by setting cookies to expire immediately
async function logoutUser(req: httpRequest, res: httpResponse) {
    const accessTokenCookie = cookie.serialize('access-token', '', {
        sameSite: "none",
        path: '/',
        secure: true,
        httpOnly: true,
        expires: new Date(0)  // Set to epoch time to expire immediately
    });

    const refreshTokenCookie = cookie.serialize('refresh-token', '', {
        sameSite: "none",
        path: '/auth/refreshtoken',
        secure: true,
        httpOnly: true,
        expires: new Date(0)  // Set to epoch time to expire immediately
    });

    res.setHeader('Set-Cookie', [accessTokenCookie, refreshTokenCookie]);
    res.redirect(302, settings.redirectSuccessUrl);
}

