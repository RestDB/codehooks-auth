import * as bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import ms from 'ms';
import { AuthStrategy } from '../types';
import { sendMail } from './mailgun';
import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { from } from 'form-data';

/**
 * OTP authentication strategy
 */
export const otpAuth: AuthStrategy = {
    settings: null,
    initialize: (cohoApp, settings) => {
        // Initialize any otp-specific settings
        otpAuth.settings = settings;
        // user uto from login form
        cohoApp.auth('/auth/otp', (req, res, next) => next()) // allow public access to otp callback
        cohoApp.post('/auth/otp', otpAuth.login)
        cohoApp.auth('/auth/otp/verify', (req, res, next) => next()) // allow public access to otp verify
        cohoApp.post('/auth/otp/verify', otpAuth.verify)
    },

    login: async (req: httpRequest, res: httpResponse) => {
        try {
            const { username } = req.body;
            //console.log('login route', username, password)
            console.debug('Login Request', req)
            let cookies = null;
            if (req.headers.cookie) {
                cookies = cookie.parse(req.headers.cookie);
                //console.log('cookies', cookies)
            }

            const db = await Datastore.open()
            const aUser = await db.getOne('users', { email: username })
            console.log('aUser', aUser)

            if (aUser) {
                const loginData = await db.updateOne('users', { email: username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
                // Generate a 6-digit OTP code
                const otpCode = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
                await db.set(`otp:${username}`, otpCode, { ttl: 60 * 1000 * 5 }); // 5 minutes
                await sendMail({email: username, otp: otpCode, from: 'jones@codehooks.io'});
                res.status(201).json({ message: "OTP sent", email: username })

            } else {
                const loginData = await db.updateOne('users', { email: username }, { $set: { lastFail: new Date().toISOString() }, $inc: { "fail": 1 } })
                console.log(loginData)
                //res.redirect(302, `${otpAuth.settings.redirectFailUrl}#code=error`)
                res.status(401).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#code=error?usernotfound=${username}` })
            }
        } catch (error: any) {
            console.error('OTP login error:', error)
            //res.redirect(302, otpAuth.settings.redirectFailUrl)
            res.status(500).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#code=error` })
        }
    },

    verify: async (req: httpRequest, res: httpResponse) => {
        const { email, otp } = req.body;
        const db = await Datastore.open()
        console.debug('verify otp', email, otp)
        const otpCode = await db.get(`otp:${email}`);
        console.debug('otpCode', otpCode);
        if (otpCode !== otp) {
            res.status(401).json({ message: "Invalid OTP" });
            return;
        }
        const aUser = await db.getOne('users', { email: email })
        console.log('aUser', aUser)

        if (aUser) {
            const loginData = await db.updateOne('users', { email: email }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            // Generate a 6-digit OTP code
            const token = jwt.sign({ email: email, id: loginData._id }, otpAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: otpAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            const refreshToken = jwt.sign({ email: email, id: loginData._id }, otpAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: otpAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            console.log('otpAuth token', otpAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE, token)
            if (otpAuth.settings.useCookie) {
                const refreshTokenCookie = cookie.serialize('refresh-token', refreshToken, {
                    sameSite: "none",
                    path: '/auth/refreshtoken',
                    secure: true,
                    httpOnly: true,
                    maxAge: Number(ms(otpAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE)) / 1000 // 8 days
                });

                const accessTokenCookie = cookie.serialize('access-token', token, {
                    sameSite: "none",
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    maxAge: Number(ms(otpAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000 // 15 minutes from now
                });

                res.setHeader('Set-Cookie', [refreshTokenCookie, accessTokenCookie]);
                console.log('PW redir', otpAuth.settings.redirectSuccessUrl)

                if (otpAuth.settings.onAuthUser) {
                    otpAuth.settings.onAuthUser(req, res, { access_token: token, user: loginData, redirectURL: otpAuth.settings.redirectSuccessUrl, method: "PASSWORD" })
                } else {
                    //res.json({"access_token": token, redirectURL: otpAuth.settings.redirectSuccessUrl})
                    console.debug('OTP Redirecting to', `${otpAuth.settings.redirectSuccessUrl}#access_token=${token}`)
                    //res.redirect(302, `${otpAuth.settings.redirectSuccessUrl}#access_token=${token}`)                
                    res.json({ redirectURL: `${otpAuth.settings.redirectSuccessUrl}#access_token=${token}` })
                }
            } else {
                // no user
                // Implement your OTP verification logic here
                res.status(501).json({ message: "OTP verification not implemented" });
            }
        } else {
            res.status(401).json({ message: "User not found" });
        }
    }
};


/**
 * Function to encrypt a password
 */
export async function encryptPassword(password: string) {
    try {
        const salt = await bcrypt.genSalt(otpAuth.settings.saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
        throw new Error('Error encrypting password');
    }
}