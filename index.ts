
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
//import * as escapeHtml from 'escape-html';
import * as crypto from "node:crypto";
import fetch from 'node-fetch';
import { google } from 'googleapis';

import { app, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';

export type authSettings = {
    userCollection?: string,
    saltRounds?: number,
    JWT_SECRET: string,
    redirectSuccessUrl?: string,
    redirectFailUrl?: string,
    useCookie?: boolean,
    baseAPIRoutes?: string,
    google?: {
        CLIENT_ID: string,
        CLIENT_SECRET: string,
        REDIRECT_URI?: string,
        SCOPE?: string | string[]
    }
}

let settings: authSettings = {
    userCollection: 'users',
    saltRounds: 10, // Number of salt rounds for hashing
    JWT_SECRET: process.env.JWT_SECRET || 'shhhhh',
    redirectSuccessUrl: '',
    redirectFailUrl: '',
    useCookie: false,
    baseAPIRoutes: '/auth'
}


export function initAuth(cohoApp: typeof app, appSettings?: authSettings) {
    // merge settings
    settings = { ...settings, ...appSettings };

    // allow public access to login api
    cohoApp.auth(`${settings.baseAPIRoutes}/login*`, (req, res, next) => {
        next()
    })

    // user/pass from login form
    cohoApp.post(`${settings.baseAPIRoutes}/login`, login)

    // custom route to create a new user
    cohoApp.post(`${settings.baseAPIRoutes}/createuser`, createUser)

    if (settings.google !== undefined) {
        // set default URI and scope
        if (!settings.google.REDIRECT_URI) {
            settings.google.REDIRECT_URI = '/oauthcallback/google'
        }
        if (!settings.google.SCOPE) {
            settings.google.SCOPE = [
                'https://www.googleapis.com/auth/userinfo.email'
            ]
        }
        // allow public access to oauth callback
        cohoApp.auth('/oauthcallback/*', (req, res, next) => {
            next()
        })
        // custom route to google auth screen
        cohoApp.get(`${settings.baseAPIRoutes}/login/google`, loginGoogle)
        // OAuth callback
        cohoApp.get('/oauthcallback/google', callbackGoogle)
        console.log('Done init google auth')
    }
    console.log('Done init auth')
    return 'OK'
}

// redirect user to Google
async function loginGoogle(req: httpRequest, res: httpResponse) {
    if (settings.google) {
        const oauth2Client = new google.auth.OAuth2(
            settings.google.CLIENT_ID,
            settings.google.CLIENT_SECRET,
            settings.google.REDIRECT_URI
        );        

        // Generate a secure random state value.
        const state = crypto.randomBytes(32).toString('hex');

        // Store state in the session for 1 minute
        const conn = await Datastore.open()
        const session_state = await conn.set(`session_state:${state}`, state, {ttl: 1000*60, keyspace: 'codehooks-auth'})
        console.log('Stored session_state', session_state)

        // Generate a url that asks permissions for the Drive activity scope
        const authorizationUrl = oauth2Client.generateAuthUrl({
            // 'online' (default) or 'offline' (gets refresh_token)
            access_type: 'offline',
            /** Pass in the scopes array defined above.
              * Alternatively, if only one scope is needed, you can pass a scope URL as a string */
            scope: settings.google.SCOPE,
            // Enable incremental authorization. Recommended as a best practice.
            include_granted_scopes: true,
            // Include the state parameter to reduce the risk of CSRF attacks.
            state: state
        });
        
        console.log('Redirect to Google', authorizationUrl)
        res.redirect(authorizationUrl)
    } else {
        res.status(400).end('Google settings not defined')
    }
}

async function callbackGoogle(req: httpRequest, res: httpResponse) {
    if (settings.google !== undefined) {
        console.log('Callback from Google', req)
        if (req.query.error) {
            console.error(req.query.error)
            res.redirect(302, settings.redirectFailUrl)
        } else {
            const { state, code, scope } = req.query;
            const oauth2Client = new google.auth.OAuth2(
                settings.google.CLIENT_ID,
                settings.google.CLIENT_SECRET,
                settings.google.REDIRECT_URI
            );
            const conn = await Datastore.open()
            const session_state = await conn.get(`session_state:${state}`, {keyspace: 'codehooks-auth'})
            console.log('State check', state, session_state)
            if (state !== session_state) { //check state value
                console.log('State mismatch. Possible CSRF attack');
                res.end('State mismatch. Possible CSRF attack');
            } else { // Get access and refresh tokens (if access_type is offline)

                let { tokens } = await oauth2Client.getToken(code);
                console.log('Tokens', tokens)

                // See documentation of personFields at
                // https://developers.google.com/people/api/rest/v1/people/get
                try {
                    // Fetch userprofile from Google
                    const opt = {
                        method: 'GET',
                        headers: {
                            "Authorization": `Bearer ${tokens.access_token}`
                        }
                    };
                    const fetchResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', opt);
                    const googleUser: any = await fetchResponse.json();
                    const email = googleUser.email;
                    console.log("Profile", googleUser);
                    const conn = await Datastore.open();
                    // upsert a user in the users collection
                    const upsertResult = await conn.updateOne('users', {"email": email},{$set: { "email": email, "google_profile": googleUser },$inc: { "visits": 1 }}, {upsert: true});
                    console.log("Upsert result", upsertResult);
                    res.redirect(302, settings.redirectSuccessUrl)
                } catch (ex) {
                    console.error(ex)
                    res.status(500).end('Error getting profile')
                }               

            }
        }
    } else {
        res.status(400).end('Google settings is not defined')
    }
}

// helper function to get the JWT
function getTokenFromAuthorizationHeader(authorizationHeader: string) {
    // Check if the authorization header is provided and starts with "Bearer "
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
        // Extract the token by removing the "Bearer " prefix
        return authorizationHeader.slice(7);
    }
    return null;
}

/**
 * Middleware to check for a valid JWT token to grant access to API routes
 */
export function authenticate(req: httpRequest, res: httpResponse, next: nextFunction) {
    console.log('Auth middleware', req)
    const token = getTokenFromAuthorizationHeader(req.headers['authorization'])
    if (token) {
        try {
            const decoded = jwt.verify(token, settings.JWT_SECRET);
            console.log('decoded jwt', decoded)
            next()
        } catch (error) {
            next('Invalid token');
        }
    } else {
        next('Missing token')
    }
}

/**
 * Check username/password agains database and generate a JWT
 */
export async function login(req: httpRequest, res: httpResponse) {
    try {
        const { username, password } = req.body;
        //console.log('login route', username, password)
        //console.log('Request', req)
        var cookies = cookie.parse(req.headers.cookie || '');
        console.log('Cookies', cookies)

        const db = await Datastore.open()
        const aUser = await db.getOne('users', { username })
        const match = await checkPassword(password, aUser.password)
        console.log('aUser', aUser, match)

        if (match) {
            const mezz = 'All good';
            const loginData = await db.updateOne('users', { username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            console.log(loginData)
            var token = jwt.sign({ username }, settings.JWT_SECRET);
            console.log('token', token)
            if (settings.useCookie) {
                res.setHeader('Set-Cookie', cookie.serialize('x-name', String('XX multiple galle stein er vondt'), {
                    httpOnly: true,
                    maxAge: 60 * 60 * 24 * 7, // 1 week
                    domain: '.api.codehooks.local.io',
                    path: '/'
                }));
            }
            if (settings.redirectSuccessUrl !== '') {
                res.redirect(302, settings.redirectSuccessUrl)
            } else {
                res.json({ token })
            }
        } else {
            const loginData = await db.updateOne('users', { username }, { $set: { lastFail: new Date().toISOString() }, $inc: { "fail": 1 } })
            console.log(loginData)
            if (settings.redirectFailUrl === '') {
                res.status(401).json({ message: "Bummer, not valid user/pass", error: true })
            } else {
                res.redirect(302, settings.redirectFailUrl)
            }
        }
    } catch (error: any) {
        console.error('User does not exists?', error)
        if (settings.redirectFailUrl === '') {
            res.status(401).json({ message: "Bummer, not a valid user/pass", error: true })
        } else {
            res.redirect(302, settings.redirectFailUrl)
        }
    }
}

/**
 * Create a user, encrypt password
 */
export async function createUser(req: httpRequest, res: httpResponse) {
    const { username, password } = req.body
    if (!username || !password) {
        return res.status(400).json({ error: "Missing required fields: username, password" })
    }
    console.log('create user route', username, password)
    const cryptPwd = await encryptPassword(password)
    console.log('Encrypt', cryptPwd)
    const db = await Datastore.open()
    const newUser = await db.insertOne('users', { username, password: cryptPwd, created: new Date() })
    res.json({ ...newUser })
}

// Function to encrypt a password
export async function encryptPassword(password: string) {
    try {
        const salt = await bcrypt.genSalt(settings.saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
        throw new Error('Error encrypting password');
    }
}

/**
 * Function to check if the input password matches the encrypted password
 */
export async function checkPassword(inputPassword: string, hashedPassword: string) {
    try {
        const match = await bcrypt.compare(inputPassword, hashedPassword);
        if (!match) console.error(inputPassword, hashedPassword, 'does not match')
        return match;
    } catch (error) {
        console.error(error)
        throw new Error('Error checking password');
    }
}