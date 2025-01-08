const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const ms = require('ms');
import { Datastore, httpRequest, httpResponse, nextFunction, filestore } from 'codehooks-js';
import { AuthSettings } from './types';

// Helper function to get the JWT from Authorization header
function getTokenFromAuthorizationHeader(authorizationHeader) {
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
        return authorizationHeader.slice(7);
    }
    return null;
}

// Refresh access token
export const refreshAccessToken = async (req: httpRequest, res: httpResponse, settings: AuthSettings) => {
    try {
        let token = getTokenFromAuthorizationHeader(req.headers['authorization'])
        if (req.headers.cookie) {
            const cookies = cookie.parse(req.headers.cookie);
            token = cookies['refresh-token']
        }
        if (!token) {
            console.error('Missing refresh token', req.headers)
            return res.status(401).json({error: "Missing refresh token"})
        }

        const decoded = jwt.verify(token, settings.JWT_REFRESH_TOKEN_SECRET);
        const claims:any = {}
        if (decoded.email) {
            claims.email = decoded.email
            claims.id = decoded.id
        }
        
        const access_token = jwt.sign(claims, settings.JWT_ACCESS_TOKEN_SECRET, 
            { expiresIn: settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE })
        
        res.setHeader('Set-Cookie', cookie.serialize('access-token', access_token, {
            sameSite: "none",
            path: '/',
            secure: true,
            httpOnly: true,
            maxAge: Number(ms(settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000
        }));
        
        res.json({access_token})
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({token_error: "Token lifetime exceeded!"})               
        } 
        console.error('refreshAccessToken', error)
        res.status(401).json({error: error.message})
    }
}

// Get JWT for access token
export const getJwtForAccessToken = async (req: httpRequest, res: httpResponse, Datastore: Datastore) => {
    console.debug('getJwtForAccessToken', req.body)
    const {access_token} = req.body;
    const conn = await Datastore.open()
    const jwt = await conn.get(`refresh-token:${access_token}`, {keyspace: 'codehooks-auth'})
    console.debug('Refresh JWT for token', jwt)
    if (jwt) {
        res.json(jwt)
    } else {
        res.status(404).json({message: "No jwt for access key"})
    }
}

// Verify access token middleware
export const verifyAccessToken = (settings: AuthSettings) => {
    return async function(req: httpRequest, res: httpResponse, next: nextFunction) {
        try {
            const db = await Datastore.open();
            let token = getTokenFromAuthorizationHeader(req.headers['authorization'])
            if (req.headers.cookie) {
                const cookies = cookie.parse(req.headers.cookie);
                token = cookies['access-token']
            }
            if (token) {
                try {
                    const decoded = jwt.verify(token, settings.JWT_ACCESS_TOKEN_SECRET);
                    req.headers['x-jwt-decoded'] = decoded;                    
                    console.debug('lookup user', { email: decoded.email, active: true })
                    const aUser = await db.getOne(settings.userCollection, { email: decoded.email, active: true });
                    console.debug('verified access token', decoded, aUser);
                    next()
                } catch (error) {
                    console.error('verifyAccessToken', error)
                    if (error.name === "TokenExpiredError") {
                        return next("Token lifetime exceeded!")               
                    }
                    
                    if (error.error) {
                        return next(error.error)
                    }                    
                    next(error);
                }
            } else {
                next('Missing token')
            }
        } catch (error) {
            console.log('verifyAccessToken Error', error)
            next(error.message)
        }
    }
}

export function setAuthCookies(res: httpResponse, token: string, refreshToken: string, settings: AuthSettings) {
    if (!settings.useCookie) return;
    
    const refreshTokenCookie = cookie.serialize('refresh-token', refreshToken, {
        sameSite: "none",
        path: '/auth/refreshtoken',
        secure: true,
        httpOnly: true,
        maxAge: Number(ms(settings.JWT_REFRESH_TOKEN_SECRET_EXPIRE)) / 1000
    });

    const accessTokenCookie = cookie.serialize('access-token', token, {
        sameSite: "none",
        path: '/',
        secure: true,
        httpOnly: true,
        maxAge: Number(ms(settings.JWT_ACCESS_TOKEN_SECRET_EXPIRE)) / 1000
    });

    res.setHeader('Set-Cookie', [refreshTokenCookie, accessTokenCookie]);
}

const ONE_DAY =  86400000;
export const setCacheHeaders = (res:httpResponse) => {
  // Set cache headers
  res.set('Cache-Control', `public, max-age=${ONE_DAY*15}, s-maxage=${ONE_DAY*15}, immutable`);
  res.setHeader("Expires", new Date(Date.now() + ONE_DAY*15).toUTCString());
  res.removeHeader('Pragma');
  res.removeHeader('Surrogate-Control');
}
