import * as bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import ms from 'ms';
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
        let cookies = null;
        if (req.headers.cookie) {
            cookies = cookie.parse(req.headers.cookie);
            //console.log('cookies', cookies)
        }

        const db = await Datastore.open()
        const aUser = await db.getOne('users', { email: username })
        const match = await checkPassword(password, aUser.password)
        console.log('aUser', aUser, match)

        if (match) {
            const loginData = await db.updateOne('users', { email: username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            console.log(loginData)
            var token = jwt.sign({ email: username, id: loginData._id }, passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            var refreshToken = jwt.sign({ email: username, id: loginData._id }, passwordAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: passwordAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            console.log('Passwordaccess token', passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE, token)
            if (passwordAuth.settings.useCookie) {
                const refreshTokenCookie = cookie.serialize('refresh-token', refreshToken, {
                    sameSite: "none",
                    path: '/auth/refreshtoken',
                    secure: true,
                    httpOnly: true,
                    maxAge: Number(ms(passwordAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE)) / 1000 // 8 days
                });

                const accessTokenCookie = cookie.serialize('access-token', token, {
                    sameSite: "none",
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    maxAge: Number(ms(passwordAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000 // 15 minutes from now
                });

                res.setHeader('Set-Cookie', [refreshTokenCookie, accessTokenCookie]);
            }
            console.log('PW redir', passwordAuth.settings.redirectSuccessUrl)
            console.log('PW cookies', res.headers)
            if (passwordAuth.settings.onAuthUser) {
                passwordAuth.settings.onAuthUser(req, res, {access_token: token, user: loginData, redirectURL: passwordAuth.settings.redirectSuccessUrl, method: "PASSWORD"})
            } else {
                //res.json({"access_token": token, redirectURL: passwordAuth.settings.redirectSuccessUrl})
                res.redirect(302, `${passwordAuth.settings.redirectSuccessUrl}#access_token=${token}`)
            }  
        } else {
            const loginData = await db.updateOne('users', { email: username }, { $set: { lastFail: new Date().toISOString() }, $inc: { "fail": 1 } })
            console.log(loginData)
            if (passwordAuth.settings.redirectFailUrl === '') {
                res.status(401).json({ message: "Bummer, not valid user/pass", error: true })
            } else {
                res.redirect(302, `${passwordAuth.settings.redirectFailUrl}#code=error`)
            }
        }
    } catch (error: any) {
        console.error('Username/pass login error:', error)
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
    const newUser = await db.updateOne('users', { email:username }, { $set: { email:username, password: cryptPwd, created: new Date() }}, {upsert: true})
    res.json({ ...newUser })
}