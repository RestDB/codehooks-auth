import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import { AuthStrategy } from '../types';
import { app, coho, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';

/**
 * Password authentication strategy
 */
export const passwordAuth: AuthStrategy = {
settings: null,
  initialize: (cohoApp, settings) => {
    // Initialize any password-specific settings
    passwordAuth.settings = settings;
    // user/pass from login form
    cohoApp.post('/auth/login', passwordAuth.login)
    // custom route to create a new user
    cohoApp.post('/auth/createuser', createUser)
  },

  login: async (req, res) => {
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
            const loginData = await db.updateOne('users', { username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            console.log(loginData)
            var token = jwt.sign({ username }, passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            var refreshToken = jwt.sign({ username }, passwordAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: passwordAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            
            if (passwordAuth.settings.useCookie) {
                res.setHeader('Set-Cookie', cookie.serialize('refresh-token', refreshToken, {
                    sameSite: "none",
                    path: '/auth/refreshtoken',
                    secure: true,
                    httpOnly: true,
                    maxAge: 60 * 60 * 8 // 8 hours                            
                }));
            }
            console.log('PW redir', passwordAuth.settings.redirectSuccessUrl)
            if (passwordAuth.settings.onAuthUser) {
                passwordAuth.settings.onAuthUser(req, res, {access_token: token, user: loginData, redirectURL: passwordAuth.settings.redirectSuccessUrl, method: "PASSWORD"})
            } else {
                res.json({"access_token": token, redirectURL: passwordAuth.settings.redirectSuccessUrl,})
            }  
        } else {
            const loginData = await db.updateOne('users', { username }, { $set: { lastFail: new Date().toISOString() }, $inc: { "fail": 1 } })
            console.log(loginData)
            if (passwordAuth.settings.redirectFailUrl === '') {
                res.status(401).json({ message: "Bummer, not valid user/pass", error: true })
            } else {
                res.redirect(302, `${passwordAuth.settings.redirectFailUrl}#code=error`)
            }
        }
    } catch (error: any) {
        console.error('User does not exists?', error)
        if (passwordAuth.settings.redirectFailUrl === '') {
            res.status(401).json({ message: "Bummer, not a valid user/pass", error: true })
        } else {
            res.redirect(302, passwordAuth.settings.redirectFailUrl)
        }
    }
  },

  // No callback needed for password auth
};


/**
 * Function to encrypt a password
 */
export async function encryptPassword(password: string) {
    try {
        const salt = await bcrypt.genSalt(passwordAuth.settings.saltRounds);
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