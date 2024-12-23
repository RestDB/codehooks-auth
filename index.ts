import { AuthSettings } from './types';
import { passwordAuth } from './strategies/passwordAuth';
import { googleAuth } from './strategies/googleAuth';
import { githubAuth } from './strategies/githubAuth';
import { otpAuth } from './strategies/otpAuth';
import handlebars from 'handlebars';
const layoutHbs = require('./auth/assets/layout.hbs');
const loginHbs = require('./auth/assets/login.hbs');
const otpHbs = require('./auth/assets/otp.hbs');
const signupHbs = require('./auth/assets/signup.hbs');
import { app, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { getJwtForAccessToken, refreshAccessToken, verifyAccessToken } from './lib';
import * as jwt from 'jsonwebtoken';
import ms from 'ms';
import * as cookie from 'cookie';
const layoutTemplate = handlebars.compile(layoutHbs);
const loginTemplate = handlebars.compile(loginHbs);
const otpTemplate = handlebars.compile(otpHbs);
const signupTemplate = handlebars.compile(signupHbs);
import { sendMail as mailgun } from './strategies/mailgun';


// TODO: add Microsoft auth
const strategies = {
    password: passwordAuth,
    google: googleAuth,
    github: githubAuth,
    otp: otpAuth
  };

// Default settings
let settings: AuthSettings = {
    userCollection: 'users', //database collection for users
    saltRounds: 10, // Number of salt rounds for hashing
    JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET || 'keep_locked_away',
    JWT_ACCESS_TOKEN_SECRET_EXPIRE: '15m',
    JWT_REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET || 'bury_in_the_sand',
    JWT_REFRESH_TOKEN_SECRET_EXPIRE: '8d',
    redirectSuccessUrl: '/',
    redirectFailUrl: '/',
    useCookie: true,
    baseAPIRoutes: '/',
    labels: {
        signinTitle: 'Sign in',
        signupTitle: 'Sign up',
        forgotTitle: 'Forgot password',
        otpTitle: 'OTP'
    },
    emailProvider: 'none'
}

// Export the AuthSettings type that's being imported
export { AuthSettings } from './types';

// Initialize authentication for a Codehooks app
export function initAuth(cohoApp: typeof app, appSettings?: AuthSettings, callback?: (req:httpRequest, res:httpResponse, payload: any)=>void) {
    try {
        // merge settings
        settings = { ...settings, ...appSettings };
        
        if (callback) {
            settings.onLoginUser = callback;
        }
        
        // Initialize strategies
        try {
            Object.values(strategies).forEach(strategy => strategy.initialize(cohoApp, settings, onSignupUser, onLoginUser, sendMail));
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
            const hasSocial = settings.github || settings.google;
            const body = loginTemplate({
                signinTitle: settings.labels.signinTitle,
                hasSocial,
                hasGoogle: settings.google,
                hasGithub: settings.github
            })
            res.send(layoutTemplate({
                contentBlock: body, 
                script: 'signin.js'
            }))
                         
        })
        cohoApp.get('/auth/signup', async (req: httpRequest, res: httpResponse) =>{
            const hasSocial = settings.github || settings.google;
            const body = signupTemplate({
                signupTitle: settings.labels.signupTitle,
                hasSocial,
                hasGoogle: settings.google,
                hasGithub: settings.github
            })
            res.send(layoutTemplate({
                contentBlock: body, 
                script: 'signin.js'
            }))
        })
        cohoApp.get('/auth/forgot', async (req: httpRequest, res: httpResponse) =>{
            console.debug('forgot template')
            res.end('Not implemented')
        })
        cohoApp.get('/auth/otp', async (req: httpRequest, res: httpResponse) =>{
            console.debug('otp template')
            const body = otpTemplate({
                otpTitle: settings.labels.otpTitle
            })
            res.send(layoutTemplate({
                contentBlock: body, 
                script: 'otp.js'
            }))
        })
        
        cohoApp.get('/auth/logout', async (req: httpRequest, res: httpResponse) => {
            logoutUser(req, res)
        })

        // serve static assets
        cohoApp.static({ route: '/auth', directory: '/auth/assets' })
        
        return 'OK'
    } catch (error) {
        console.error('initAuth', error)
        return 'Error initializing auth'
    }
}

// Add this new function before onSignupUser
function setAuthCookies(res: httpResponse, token: string, refreshToken: string) {
    if (!settings.useCookie) return;
    
    const refreshTokenCookie = cookie.serialize('refresh-token', refreshToken, {
        sameSite: "none",
        path: '/auth/refreshtoken',
        secure: true,
        httpOnly: true,
        maxAge: Number(ms(settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE)) / 1000
    });

    const accessTokenCookie = cookie.serialize('access-token', token, {
        sameSite: "none",
        path: '/',
        secure: true,
        httpOnly: true,
        maxAge: Number(ms(settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000
    });

    res.setHeader('Set-Cookie', [refreshTokenCookie, accessTokenCookie]);
}

// TODO: add mail strategy
function sendMail(content: Object): Promise<any> {
    return new Promise((resolve, reject) => {
        try {
            console.debug('sendMail', content);
            
            // Select email provider and settings based on configuration
            const emailProvider = settings.emailProvider || 'mailgun';
            let from: string;
            
            switch (emailProvider.toLowerCase()) {
                case 'none':
                    console.debug('No email provider selected');
                    reject({message: 'No email provider selected'});
                    break;
                case 'mailgun':
                    const otp = content['otp'];
                    const text = `Hi there! Here's your one time password: ${otp}`;
                    const html = `Hi there! <br/>Here's your one time password: <b>${otp}</b><br/>Best regards, the X team.`;
                    const subject = 'One-Time Password';
                    const to = content['to'];
                    return mailgun(settings.emailSettings.mailgun,{...content, text, html, subject, to}).then(resolve).catch(reject);
                    
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

// Called after successful signup strategy
async function onSignupUser(req: httpRequest, res: httpResponse, payload: any) {
    return new Promise(async (resolve, reject) => {
        const db = await Datastore.open();
        let signupData = null;
        console.debug('onSignupUser', payload)
        
        // user does not exist, create new user
        signupData = await db.updateOne(settings.userCollection, {email: payload.email}, {$set: {email: payload.email, firstLogin: new Date().toISOString(), ...payload}}, {upsert: true})
        console.debug('signupData', signupData)
        const token = jwt.sign({ email: payload.email, id: signupData._id }, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
        const refreshToken = jwt.sign({ email: payload.email, id: signupData._id }, settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
        if (settings.onSignupUser) {
            settings.onSignupUser(req, res, {access_token: token, user: signupData})
        } else if (settings.useCookie) {
            setAuthCookies(res, token, refreshToken);
        }
          
        console.debug('Signup Redirecting to', `${settings.redirectSuccessUrl}#access_token=${token}&signup=true`)
        //res.redirect(302, `${settings.redirectSuccessUrl}#access_token=${token}&signup=true`)
        resolve({ token, refreshToken })
    })  
}

// Called after successful login strategy
async function onLoginUser(req: httpRequest, res: httpResponse, payload: any) {
    return new Promise(async (resolve, reject) => { 
        const db = await Datastore.open();
        try {
            const aUser = await db.getOne(settings.userCollection, { email: payload.email })
            console.debug('onLoginUser', aUser)
            const token = jwt.sign({ email: aUser.email, id: aUser._id }, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            const refreshToken = jwt.sign({ email: aUser.email, id: aUser._id }, settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            console.log('Github access token', settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE, token)
            if (settings.onLoginUser) {
                settings.onLoginUser(req, res, {access_token: token, user: aUser})
            } else if (settings.useCookie) {
                setAuthCookies(res, token, refreshToken);
            }
            await db.updateOne(settings.userCollection, { email: payload.email }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })  
            console.debug('Github login Redirecting to', `${settings.redirectSuccessUrl}#access_token=${token}&login=true`)
            //res.redirect(302, `${settings.redirectSuccessUrl}#access_token=${token}&login=true`)
            resolve({ token, refreshToken })
        } catch (error) {
            reject({error: "User not found"})
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

