import * as crypto from "node:crypto";
import fetch from 'node-fetch';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import { google } from 'googleapis';
import { AuthStrategy } from '../types';
import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
// ... (import other necessary modules)

export const googleAuth: AuthStrategy = {
  settings: null,
  initialize: (cohoApp, settings) => {
    // Initialize Google-specific settings
    googleAuth.settings = settings;
    // set default URI and scope
    if (!settings.google.REDIRECT_URI) {
        settings.google.REDIRECT_URI = '/auth/oauthcallback/google'
    }
    if (!settings.google.SCOPE) {
        settings.google.SCOPE = [
            'https://www.googleapis.com/auth/userinfo.email'
        ]
    }
    // allow public access to oauth callback
    cohoApp.auth('/auth/oauthcallback/*', (req, res, next) => {
        next()
    })
    // custom route to google auth screen
    cohoApp.get('/auth/login/google', googleAuth.login)
    // OAuth callback
    cohoApp.get('/auth/oauthcallback/google', (req, res, next) => {
      if (googleAuth.callback) {
        googleAuth.callback(req, res, next);
      } else {
        next('Google Auth callback not implemented');
      }
    });
        
  },

  login: async (req:httpRequest, res:httpResponse) => {
    // Implement Google login logic
    if (googleAuth.settings.google) {
        const oauth2Client = new google.auth.OAuth2(
            googleAuth.settings.google.CLIENT_ID,
            googleAuth.settings.google.CLIENT_SECRET,
            googleAuth.settings.google.REDIRECT_URI
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
            scope: googleAuth.settings.google.SCOPE,
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
  },

  callback: async (req:httpRequest, res:httpResponse) => {
    // Implement Google callback logic
    if (googleAuth.settings.google !== undefined) {
        console.log('Callback from Google', req)
        if (req.query.error) {
            console.error(req.query.error)
            res.redirect(302, googleAuth.settings.redirectFailUrl)
        } else {
            const { state, code, scope } = req.query;
            const oauth2Client = new google.auth.OAuth2(
                googleAuth.settings.google.CLIENT_ID,
                googleAuth.settings.google.CLIENT_SECRET,
                googleAuth.settings.google.REDIRECT_URI
            );
            const conn = await Datastore.open()
            const session_state = await conn.get(`session_state:${state}`, {keyspace: 'codehooks-auth'})
            console.log('State check', state, session_state)
            if (state !== session_state) { //check state value
                console.log('State mismatch. Possible CSRF attack');
                res.end('State mismatch. Possible CSRF attack');
            } else { // Get access and refresh tokens (if access_type is offline)
                // delete session key
                conn.del(`session_state:${state}`, {keyspace: 'codehooks-auth'})

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
                    const acctokkey = crypto.randomBytes(32).toString('hex');

                    
                    var token = jwt.sign({ email }, googleAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: googleAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
                    var refreshToken = jwt.sign({ email }, googleAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: googleAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
                    // Store JWT in the session for 1 minute
                    await conn.set(`refresh-token:${refreshToken}`, refreshToken, {ttl: 1000*60*8, keyspace: 'codehooks-auth'})
                    
                    if (googleAuth.settings.useCookie) {
                        res.setHeader('Set-Cookie', cookie.serialize('refresh-token', refreshToken, {
                            sameSite: "none",
                            path: '/auth/refreshtoken',
                            secure: true,
                            httpOnly: true,
                            maxAge: 60 * 60 * 8 // 8 hours                            
                        }));
                    }
                    if (googleAuth.settings.onAuthUser) {
                        googleAuth.settings.onAuthUser(req, res, {access_token: token, user: upsertResult, method: "GOOGLE"})
                    } else {
                        res.redirect(302, `${googleAuth.settings.redirectSuccessUrl}#access_token=${token}`)
                    }                    
                } catch (ex) {
                    console.error(ex)
                    res.status(500).end('Error getting profile')
                }               

            }
        }
    } else {
        res.status(400).end('Google settings is not defined')
    }
  },
};