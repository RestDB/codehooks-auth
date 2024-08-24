"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticate = authenticate;
exports.login = login;
exports.createUser = createUser;
exports.encryptPassword = encryptPassword;
exports.checkPassword = checkPassword;
const bcrypt = __importStar(require("bcryptjs"));
const jwt = __importStar(require("jsonwebtoken"));
const cookie = __importStar(require("cookie"));
//import * as escapeHtml from 'escape-html';
const codehooks_js_1 = require("codehooks-js");
const saltRounds = 10; // Number of salt rounds for hashing
const JWT_SECRET = process.env.JWT_SECRET || 'shhhhh';
// helper function to get the JWT
function getTokenFromAuthorizationHeader(authorizationHeader) {
    // Check if the authorization header is provided and starts with "Bearer "
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
        // Extract the token by removing the "Bearer " prefix
        return authorizationHeader.slice(7);
    }
    return null;
}
// Not allowed to manipulate users collection
const deny = new RegExp('users');
console.log("Init deny func", deny);
codehooks_js_1.app.use(deny, (req, res, next) => {
    console.log("Global deny hook", req);
    if (req.method !== 'GET') {
        return res.status(401).json({ error: 'Not allowed to access users data' });
    }
    return next();
});
/**
 * Middleware to check for a valid JWT token to grant access to API routes
 */
function authenticate(req, res, next) {
    console.log('Auth middleware', req);
    const token = getTokenFromAuthorizationHeader(req.headers['authorization']);
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            console.log('decoded jwt', decoded);
            next();
        }
        catch (error) {
            next('Invalid token');
        }
    }
    else {
        next('Missing token');
    }
}
/**
 * Check username/password agains database and generate a JWT
 */
function login(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const { username, password } = req.body;
            //console.log('login route', username, password)
            //console.log('Request', req)
            var cookies = cookie.parse(req.headers.cookie || '');
            console.log('Cookies', cookies);
            const db = yield codehooks_js_1.Datastore.open();
            const aUser = yield db.getOne('users', { username });
            const match = yield checkPassword(password, aUser.password);
            console.log('aUser', aUser, match);
            if (match) {
                const mezz = 'All good';
                const loginData = yield db.updateOne('users', { username }, { $set: { lastLogin: new Date().toISOString() }, $inc: { "success": 1 } });
                console.log(loginData);
                var token = jwt.sign({ username }, JWT_SECRET);
                console.log('token', token);
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
                res.redirect('/dev/static/dashboard.html');
                //res.json({message: mezz, token});
            }
            else {
                const loginData = yield db.updateOne('users', { username }, { $set: { lastFail: new Date().toISOString() }, $inc: { "fail": 1 } });
                console.log(loginData);
                res.status(401).json({ message: "Bummer, not valid user/pass", error: true });
            }
        }
        catch (error) {
            console.error(error);
            res.status(400).json({ message: error.message, error: true });
        }
    });
}
/**
 * Create a user, encrypt password
 */
function createUser(req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Missing required fields: username, password" });
        }
        console.log('create user route', username, password);
        const cryptPwd = yield encryptPassword(password);
        console.log('Encrypt', cryptPwd);
        const db = yield codehooks_js_1.Datastore.open();
        const newUser = yield db.insertOne('users', { username, password: cryptPwd, created: new Date() });
        res.json(Object.assign({}, newUser));
    });
}
// Function to encrypt a password
function encryptPassword(password) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const salt = yield bcrypt.genSalt(saltRounds);
            const hashedPassword = yield bcrypt.hash(password, salt);
            return hashedPassword;
        }
        catch (error) {
            throw new Error('Error encrypting password');
        }
    });
}
/**
 * Function to check if the input password matches the encrypted password
 */
function checkPassword(inputPassword, hashedPassword) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const match = yield bcrypt.compare(inputPassword, hashedPassword);
            if (!match)
                console.error(inputPassword, hashedPassword, 'does not match');
            return match;
        }
        catch (error) {
            console.error(error);
            throw new Error('Error checking password');
        }
    });
}
