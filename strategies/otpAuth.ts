import * as bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import ms from 'ms';
import { AuthStrategy } from '../types';
import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
import { setAuthCookies } from '../lib';

/**
 * OTP authentication strategy
 */
export const otpAuth: AuthStrategy = {
    settings: null,
    onSignupUser: null,
    onLoginUser: null,
    sendOTPMail: null,
    initialize: (cohoApp, settings, onSignupUser, onLoginUser, sendOTPMail) => {
        otpAuth.onSignupUser = onSignupUser;
        otpAuth.onLoginUser = onLoginUser;
        otpAuth.sendOTPMail = sendOTPMail;
        // Initialize any otp-specific settings
        otpAuth.settings = settings;
        // user uto from login form
        cohoApp.auth('/auth/otp', (req, res, next) => next()) // allow public access to otp callback
        cohoApp.post('/auth/otp', otpAuth.login)
        cohoApp.auth('/auth/otp/verify', (req, res, next) => next()) // allow public access to otp verify
        cohoApp.post('/auth/otp/verify', otpAuth.verify)
        cohoApp.get('/auth/otp/verify', otpAuth.verify)
    },

    login: async (req: httpRequest, res: httpResponse) => {
        try {
            const db = await Datastore.open();
            const { username, signup } = req.body;
            // Generate a 6-digit OTP code
            const otpCode = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
            let signupData = null;
            //console.log('login route', username, password)
            console.log('Login Request', req)
            if (signup && signup === 'true') {                
                await otpAuth.onSignupUser(req, res, { email: username, ...req.body, otp: otpCode })
            } else {
                const aUser = await db.getOne(otpAuth.settings.userCollection, { email: username })
                if (otpAuth.settings.onLoginUser) {
                    try {
                        otpAuth.settings.onLoginUser(req, res, {access_token: otpCode, user: aUser})
                    } catch (error) {
                        console.error('Error in onLoginUser otpAuth override', error)
                        res.status(401).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#error=${error.message}` })
                    }
                } 
                
                await otpAuth.sendOTPMail({to: username, otp: otpCode});                
            }            
            
            console.debug('otpCode', otpCode)
            await db.set(`otp:${username}`, otpCode, { ttl: 60 * 1000 * 5 }); // 5 minutes
            
            // res.redirect(302, `${settings.redirectSuccessUrl}#access_token=${token}&signup=true`)
            res.status(201).json({ message: "OTP sent", email: username })
            
        } catch (error: any) {
            console.error('OTP login error:', error)
            //res.redirect(302, otpAuth.settings.redirectFailUrl)
            res.status(401).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#error=${error.message}` })
        }
    },

    verify: async (req: httpRequest, res: httpResponse) => {
        let { email, otp } = req.body;
        if (req.method === 'GET') {
            email = req.query.email;
            otp = req.query.otp;
        }
        const db = await Datastore.open()
        console.debug('verify otp', otp, email)
        const otpCode = await db.get(`otp:${email}`);
        console.debug('otpCode', otpCode);
        if (otpCode !== otp) {
            res.status(401).json({ message: "Invalid OTP" });
            return;
        }
        const aUser = await db.getOne(otpAuth.settings.userCollection, { email: email })
        console.log('aUser', aUser)

        if (aUser) {
            if (otpAuth.settings.onLoginUser) {
                try {
                    otpAuth.settings.onLoginUser(req, res, {access_token: otpCode, user: aUser})
                } catch (error) {
                    console.error('Error in onLoginUser otpAuth override', error)
                    res.status(401).json({ redirectURL: `${otpAuth.settings.redirectFailUrl}#error=${error.message}` })
                }
            }
            const activate = await db.get(`activate-otp:${email}`, otp)
            const isActive = aUser.active || (activate ? true : false)
            const loginData = await db.updateOne(otpAuth.settings.userCollection, { email: email }, { $set: {active: isActive, lastLogin: new Date().toISOString() }, $inc: { "success": 1 } })
            // generate token
            const token = jwt.sign({ email: email, id: loginData._id }, otpAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: otpAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
            const refreshToken = jwt.sign({ email: email, id: loginData._id }, otpAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: otpAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
            console.log('otpAuth token', otpAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE, token)
            if (otpAuth.settings.useCookie) {
                setAuthCookies(res, token, refreshToken, otpAuth.settings)                
                if (otpAuth.settings.onAuthUser) {
                    otpAuth.settings.onAuthUser(req, res, { access_token: token, user: loginData, redirectURL: otpAuth.settings.redirectSuccessUrl, method: "PASSWORD" })
                } else {
                    if (req.method === 'GET') {
                        res.redirect(302, `${otpAuth.settings.redirectSuccessUrl}#access_token=${token}`)
                    } else {
                        res.json({ redirectURL: `${otpAuth.settings.redirectSuccessUrl}#access_token=${token}` })
                    }
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