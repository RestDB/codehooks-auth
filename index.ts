import { AuthSettings } from './types';
import { passwordAuth } from './strategies/passwordAuth';
import { googleAuth } from './strategies/googleAuth';
import { githubAuth } from './strategies/githubAuth';
import { otpAuth } from './strategies/otpAuth';
import { app, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { getJwtForAccessToken, refreshAccessToken, verifyAccessToken } from './lib';

// TODO: add github auth
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
    baseAPIRoutes: '/'
}

// Initialize authentication for a Codehooks app
export function initAuth(cohoApp: typeof app, appSettings?: AuthSettings, callback?: (req:httpRequest, res:httpResponse, payload: any)=>void) {
    try {
        // merge settings
        settings = { ...settings, ...appSettings };
        
        if (callback) {
            settings.onAuthUser = callback;
        }
        
        // Initialize strategies
        try {
            Object.values(strategies).forEach(strategy => strategy.initialize(cohoApp, settings));
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
        
        cohoApp.use('/auth/login', (req: httpRequest, res: httpResponse, next: nextFunction) =>{
            req.apiPath = '/auth/login.html'
            next()
        })
        cohoApp.use('/auth/signup', (req: httpRequest, res: httpResponse, next: nextFunction) =>{
            req.apiPath = '/auth/signup.html'
            next()
        })
        cohoApp.use('/auth/forgot', (req: httpRequest, res: httpResponse, next: nextFunction) =>{
            req.apiPath = '/auth/forgot.html'
            next()
        })
        cohoApp.use('/auth/otp', (req: httpRequest, res: httpResponse, next: nextFunction) =>{
            req.apiPath = '/auth/otp.html'
            next()
        })
        
        return 'OK'
    } catch (error) {
        console.error('initAuth', error)
        return 'Error initializing auth'
    }
}



