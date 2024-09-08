import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import { AuthSettings } from './types';
import { passwordAuth } from './strategies/passwordAuth';
import { googleAuth } from './strategies/googleAuth';
import { app, Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';

const strategies = {
    password: passwordAuth,
    google: googleAuth,
  };


let settings: AuthSettings = {
    userCollection: 'users', //database collection for users
    saltRounds: 10, // Number of salt rounds for hashing
    JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET || 'keep_locked_away',
    JWT_ACCESS_TOKEN_SECRET_EXPIRE: '10m',
    JWT_REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET || 'bury_in_the_sand',
    JWT_REFRESH_TOKEN_SECRET_EXPIRE: '8h',
    redirectSuccessUrl: '',
    redirectFailUrl: '',
    useCookie: true,
    baseAPIRoutes: '/'
}


export function initAuth(cohoApp: typeof app, appSettings?: AuthSettings, callback?: (req:httpRequest, res:httpResponse, payload: any)=>void) {
    // merge settings
    settings = { ...settings, ...appSettings };
    if (callback) {
        settings.onAuthUser = callback;
    }
    
    // Initialize strategies
    Object.values(strategies).forEach(strategy => strategy.initialize(cohoApp, settings));
    
    // allow public access to login api
    cohoApp.auth('/auth/login*', (req, res, next) => {
        next()
    })


    
    // route to get jwt from access token
    cohoApp.auth('/auth/accesstoken', (req, res, next) => {next()})   
    cohoApp.post('/auth/accesstoken', getJwtForAccessToken)   
    // route to refresh access token
    cohoApp.auth('/auth/refreshtoken', (req, res, next) => {next()})   
    cohoApp.post('/auth/refreshtoken', refreshAccessToken)
    // protect this API with a JWT
    cohoApp.auth(`${settings.baseAPIRoutes}/*`, verifyAccessToken)
    return 'OK'
}

// refresh access token
async function refreshAccessToken(req:httpRequest, res: httpResponse) {
    try {
        const cookies = cookie.parse(req.headers.cookie);
        const token = cookies['refresh-token'];
        console.log('Auth refresh-token', token)
        const decoded:any = jwt.verify(token, settings.JWT_REFRESH_TOKEN_SECRET);
        console.log('verified refresh token', decoded)
        const claims:any = {}
        if (decoded.username) {
            claims.username = decoded.username
        } else if (decoded.email) {
            claims.email = decoded.email
        }
        var access_token = jwt.sign(claims, settings.JWT_ACCESS_TOKEN_SECRET, { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE })
        res.json({access_token})
    } catch (error:any) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({token_error: "Token lifetime exceeded!"})               
        } 
        console.error(error)
        res.status(401).json({error: error.message})
    }
}

// post access token and get jwt
async function getJwtForAccessToken(req: httpRequest, res: httpResponse) {
    console.debug('getJwtForAccessToken', req.body)
    const {access_token} = req.body;
    const conn = await Datastore.open()
    const jwt = await conn.get(`refresh-token:${access_token}`, {keyspace: 'codehooks-auth'})
    console.debug('Refresj JWT for token', jwt)
    if (jwt) {
        // remove after usage one time
        //conn.del(`jwt:${access_token}`, {keyspace: 'codehooks-auth'})
        res.json(jwt)
    } else {
        res.status(404).json({message: "No jwt for access key"})
    }
}

// auth middleware
function verifyAccessToken(req: httpRequest, res: httpResponse, next: nextFunction) {    
    try {
        if (!req.headers.authorization) {
            console.log('Missing auth header', req)
            res.status(403).end('Missing auth header')
        }
        //const cookies = cookie.parse(req.headers.cookie);
        //console.log('Auth access-token', cookies['access-token'] ? cookies['access-token'] : 'no tok')
        const token = getTokenFromAuthorizationHeader(req.headers['authorization'])
        if (token) {
            try {
                const decoded = jwt.verify(token, settings.JWT_ACCESS_TOKEN_SECRET);
                console.log('verified access token', decoded, req.headers.cookie)
                next()
            } catch (error:any) {
                if (error.name === "TokenExpiredError") {
                    return next("Token lifetime exceeded!")               
                }        
                next(error);
            }
        } else {
            next('Missing token')
        }
    } catch (error:any) {
        console.log('verifyAccessToken Error', error)
        next(error.message)
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



