import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
//import * as escapeHtml from 'escape-html';

import { Datastore, httpRequest, httpResponse, nextFunction } from 'codehooks-js';
const saltRounds = 10; // Number of salt rounds for hashing

const JWT_SECRET = process.env.JWT_SECRET || 'shhhhh';

// helper function to get the JWT
function getTokenFromAuthorizationHeader(authorizationHeader: string) {
    // Check if the authorization header is provided and starts with "Bearer "
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
        // Extract the token by removing the "Bearer " prefix
        return authorizationHeader.slice(7);
    }
    return null;
}

/**
 * Middleware to check for a valid JWT token to grant access to API routes
 */
export function authenticate(req: httpRequest, res: httpResponse, next:nextFunction) {
    console.log('Auth middleware', req)
    const token = getTokenFromAuthorizationHeader(req.headers['authorization'])
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            console.log('decoded jwt', decoded)
            next()            
        } catch (error) {
            next('Invalid token');
        }        
    } else {
        next('Missing token')
    }    
}

/**
 * Check username/password agains database and generate a JWT
 */
export async function login(req: httpRequest, res: httpResponse) {    
    try {
        const {username, password} = req.body;
        //console.log('login route', username, password)
        //console.log('Request', req)
        var cookies = cookie.parse(req.headers.cookie || '');
        console.log('Cookies', cookies)
    
        const db = await Datastore.open()
        const aUser = await db.getOne('users', {username})
        const match = await checkPassword(password, aUser.password)
        console.log('aUser', aUser, match)
        
        if (match) {
            const mezz = 'All good';
            const loginData = await db.updateOne('users', {username}, {$set: {lastLogin: new Date().toISOString()}, $inc: {"success": 1}})
            console.log(loginData)
            var token = jwt.sign({ username }, JWT_SECRET);
            console.log('token', token)
            //res.redirect('/static/dashboard.html'); 
            /*
            const cookieName = 'cohoSession';
            const cookieValue = 'cookieValue';
            const maxAge = 24 * 60 * 60; // 1 year in seconds
            const domain = '.api.codehooks.local.io'; // Replace with your actual domain

            // Create the cookie string
            const mycookie = `${cookieName}=${cookieValue}; Max-Age=${maxAge}; Domain=${domain}; Path=/; HttpOnly`;
            res.setHeader('Set-Cookie', mycookie);
            */
            
            res.setHeader('Set-Cookie', cookie.serialize('x-name', String('XX multiple galle stein er vondt'), {
                httpOnly: true,
                maxAge: 60 * 60 * 24 * 7, // 1 week
                domain: '.api.codehooks.local.io',
                path: '/'
              }));
          
            //res.statusCode = 302;
            //res.setHeader('location', '/dev/static/dashboard.html');
            //res.status(302).end();
            res.redirect('/dev/static/dashboard.html')
            //res.json({message: mezz, token});
        } else {
            const loginData = await db.updateOne('users', {username}, {$set: {lastFail: new Date().toISOString()}, $inc: {"fail": 1}})
            console.log(loginData)
            res.status(401).json({message: "Bummer, not valid user/pass", error: true})
        }   
    } catch (error: any) {
        console.error(error)
        res.status(400).json({message: error.message, error: true})
    }
}

/**
 * Create a user, encrypt password
 */
export async function createUser(req: httpRequest, res: httpResponse) {
    const {username, password} = req.body
    if (!username || !password) {
        return res.status(400).json({error: "Missing required fields: username, password"})
    }
    console.log('create user route', username, password)
    const cryptPwd = await encryptPassword(password)
    console.log('Encrypt', cryptPwd)
    const db = await Datastore.open()
    const newUser = await db.insertOne('users', {username, password: cryptPwd, created: new Date()})
    res.json({...newUser})
}

// Function to encrypt a password
export async function encryptPassword(password: string) {
    try {
        const salt = await bcrypt.genSalt(saltRounds);
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