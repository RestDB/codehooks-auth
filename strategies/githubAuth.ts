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
  onSignupUser: null,
  onLoginUser: null,
  sendMail: null,
  initialize: (cohoApp, settings, onSignupUser, onLoginUser, sendMail) => {
    // Initialize GitHub-specific settings
    if (!settings.github) {
      console.error('GitHub settings are required')
      return
    }
    githubAuth.settings = settings;
    githubAuth.onSignupUser = onSignupUser;
    githubAuth.onLoginUser = onLoginUser;
    githubAuth.sendMail = sendMail;
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
    cohoApp.get('/auth/signup/github', githubAuth.signup )
  },

  signup: async (req: httpRequest, res: httpResponse) => {
    console.log('signup github')
    req.headers['signup-flow'] = true;
    githubAuth.login(req, res)
  },

  login: async (req: httpRequest, res: httpResponse) => {
    if (githubAuth.settings.github) {
      const state = crypto.randomBytes(32).toString('hex');
      const conn = await Datastore.open()
      await conn.set(`session_state:${state}`, JSON.stringify({state, signup: req.headers['signup-flow'] || false}), {ttl: 1000*60, keyspace: 'codehooks-auth'})

      const authorizationUrl = `https://github.com/login/oauth/authorize?` +
        `client_id=${githubAuth.settings.github.CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(githubAuth.settings.github.REDIRECT_URI)}` +
        `&scope=${encodeURIComponent(githubAuth.settings.github.SCOPE)}` +
        `&state=${state}`

      console.log('Redirect to GitHub', authorizationUrl)
      res.redirect(authorizationUrl)
    } else {
      res.status(400).end('GitHub settings not defined')
    }
  },

  callback: async (req: httpRequest, res: httpResponse) => {
    if (githubAuth.settings.github) {
      // ... (state validation logic) ...

      const { code, state } = req.query;
      // check state
      const conn = await Datastore.open()
      const session_state = JSON.parse(await conn.get(`session_state:${state}`, {keyspace: 'codehooks-auth'}))
      console.debug('State check', state, session_state)
      if (state !== session_state.state) { //check state value
          console.error('State mismatch. Possible CSRF attack');
          res.status(401).end('Something went wrong');
          return;
      }
      // delete session key
      conn.del(`session_state:${state}`, {keyspace: 'codehooks-auth'})

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
      
      try { 
        if (session_state.signup) {
          console.debug('Signup flow', session_state.signup)
          const {token, refreshToken} = await githubAuth.onSignupUser(req, res, { ...githubUser })          
          res.redirect(302, `${githubAuth.settings.redirectSuccessUrl}#access_token=${token}&refresh_token=${refreshToken}&signup=true`)     
        } else {
          console.debug('Login flow', session_state.signup)
          const {token, refreshToken} = await githubAuth.onLoginUser(req, res, { ...githubUser }) 
          res.redirect(302, `${githubAuth.settings.redirectSuccessUrl}#access_token=${token}&refresh_token=${refreshToken}&login=true`)     
        } 
      } catch (error) {
        console.error('Error during signup or login', error)
        //res.status(400).json({error, message: 'Something went wrong'})
        res.redirect(302, `${githubAuth.settings.redirectFailUrl}#error=${error.error}`)
        return
      }      
      
    } else {
      res.status(400).end('GitHub settings is not defined')
    }
  },
};
