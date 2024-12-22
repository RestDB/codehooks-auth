import * as bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import ms from 'ms';
import { AuthStrategy } from '../types';
import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { from } from 'form-data';
import { sign } from 'crypto';

/**
 * OTP authentication strategy
 */
export const otpAuth: AuthStrategy = {
    settings: null,
    onSignupUser: null,
    onLoginUser: null,
    sendMail: null,
    initialize: (cohoApp, settings, onSignupUser, onLoginUser, sendMail) => {
        otpAuth.onSignupUser = onSignupUser;
        otpAuth.onLoginUser = onLoginUser;
        otpAuth.sendMail = sendMail;
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
            const db = await Datastore.open();
            const { username, signup } = req.body;
            let signupData = null;
            //console.log('login route', username, password)
            console.log('Login Request', req)
            if (signup && signup === 'true') {                
                await otpAuth.onSignupUser(req, res, { email: username, ...req.body })
            }
            console.log('Lookup user', username)
            
            const aUser = await db.getOne('users', { email: username })
            console.debug('aUser', aUser)

            //const loginData = await db.updateOne('users', { email: username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            //console.debug('loginData exists', loginData)
            // Generate a 6-digit OTP code
            const otpCode = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
            console.debug('otpCode', otpCode)
            await db.set(`otp:${username}`, otpCode, { ttl: 60 * 1000 * 5 }); // 5 minutes
            await otpAuth.sendMail({to: username, otp: otpCode});
            // res.redirect(302, `${settings.redirectSuccessUrl}#access_token=${token}&signup=true`)
            res.status(201).json({ message: "OTP sent", email: username })
            
        } catch (error: any) {
            console.error('OTP login error:', error)
            //res.redirect(302, otpAuth.settings.redirectFailUrl)
            res.status(401).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#error=${error.message}` })
        }
    },

    verify: async (req: httpRequest, res: httpResponse) => {
        const { email, otp } = req.body;
        const db = await Datastore.open()
        console.debug('verify otp', req.body)
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