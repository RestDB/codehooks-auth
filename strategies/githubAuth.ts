import * as crypto from "node:crypto";
import fetch from 'node-fetch';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import ms from 'ms';
import { AuthStrategy } from '../types';
import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';

/**
 * GitHub authentication strategy
 */
export const githubAuth: AuthStrategy = {
  settings: null,
  initialize: (cohoApp, settings) => {
    // Initialize GitHub-specific settings
    if (!settings.github) {
      console.error('GitHub settings are required')
      return
  }
    githubAuth.settings = settings;
    // set default URI and scope
    if (!settings.github.REDIRECT_URI) {
        settings.github.REDIRECT_URI = '/auth/oauthcallback/github'
    }
    if (!settings.github.SCOPE) {
        settings.github.SCOPE = 'user:email'
    }
    // allow public access to oauth callback
    cohoApp.auth('/auth/oauthcallback/*', (req, res, next) => {
        next()
    })
    // custom route to github auth screen
    cohoApp.get('/auth/login/github', githubAuth.login)
    // OAuth callback
    cohoApp.get('/auth/oauthcallback/github', (req, res, next) => {
      if (githubAuth.callback) {
        githubAuth.callback(req, res, next);
      } else {
        next('GitHub Auth callback not implemented');
      }
    });
  },

  login: async (req: httpRequest, res: httpResponse) => {
    if (githubAuth.settings.github) {
      const state = crypto.randomBytes(32).toString('hex');
      const conn = await Datastore.open()
      await conn.set(`session_state:${state}`, state, {ttl: 1000*60, keyspace: 'codehooks-auth'})

      const authorizationUrl = `https://github.com/login/oauth/authorize?` +
        `client_id=${githubAuth.settings.github.CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(githubAuth.settings.github.REDIRECT_URI)}` +
        `&scope=${encodeURIComponent(githubAuth.settings.github.SCOPE)}` +
        `&state=${state}`;

      console.log('Redirect to GitHub', authorizationUrl)
      res.redirect(authorizationUrl)
    } else {
      res.status(400).end('GitHub settings not defined')
    }
  },

  callback: async (req: httpRequest, res: httpResponse) => {
    if (githubAuth.settings.github) {
      // ... (state validation logic) ...

      const { code } = req.query;
      
      // Exchange code for access token
      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client_id: githubAuth.settings.github.CLIENT_ID,
          client_secret: githubAuth.settings.github.CLIENT_SECRET,
          code: code,
          redirect_uri: githubAuth.settings.github.REDIRECT_URI
        })
      });
      const tokenData = await tokenResponse.json() as { access_token: string };
      const access_token = tokenData.access_token;

      // Fetch user profile
      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `token ${access_token}`
        }
      });

      const githubUser: any = await userResponse.json();
      const email = githubUser.email;

      // upsert a user in the users collection
      const conn = await Datastore.open();
      const upsertResult = await conn.updateOne('users', {"email": email},{$set: { "email": email, "github_profile": githubUser },$inc: { "visits": 1 }}, {upsert: true});
      console.log("Upsert result", upsertResult);
      const acctokkey = crypto.randomBytes(32).toString('hex');

      
      const token = jwt.sign({ email, id: upsertResult._id }, githubAuth.settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: githubAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE });
      const refreshToken = jwt.sign({ email, id: upsertResult._id }, githubAuth.settings.JWT_REFRESH_TOKEN_SECRET, { expiresIn: githubAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE });
      console.log('Github access token', githubAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE, token)

      if (githubAuth.settings.useCookie) {
        const refreshTokenCookie = cookie.serialize('refresh-token', refreshToken, {
            sameSite: "none",
            path: '/auth/refreshtoken',
            secure: true,
            httpOnly: true,
            maxAge: Number(ms(githubAuth.settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE)) / 1000 // 8 days
        });

        const accessTokenCookie = cookie.serialize('access-token', token, {
            sameSite: "none",
            path: '/',
            secure: true,
            httpOnly: true,
            maxAge: Number(ms(githubAuth.settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000 // 15 minutes from now
        });

        res.setHeader('Set-Cookie', [refreshTokenCookie, accessTokenCookie]);
      }

      if (githubAuth.settings.onAuthUser) {
        githubAuth.settings.onAuthUser(req, res, {access_token: token, user: upsertResult, method: "GITHUB"})
      } else {
        console.debug('Github Redirecting to', `${githubAuth.settings.redirectSuccessUrl}#access_token=${token}`)
        res.redirect(302, `${githubAuth.settings.redirectSuccessUrl}#access_token=${token}`)
      }
    } else {
      res.status(400).end('GitHub settings is not defined')
    }
  },
};
