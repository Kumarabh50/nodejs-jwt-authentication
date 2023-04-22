import express from 'express';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

dotenv.config({path: './config/env.config'})
const app = express();

// middlewares
app.use(bodyParser.json())
app.use(cookieParser());

const jwtExpirySeconds = 60;
const jwtKey = 'secret_key';

const authorization = (req, res, next) => {
    const {userId, password} = req.body;
    if(!userId || !password) {
        return res.status(400).json({message: 'Missing credentials.'})
    }

    if(userId === 'admin' && password === 'admin') {
        const token = jwt.sign({userId, password}, jwtKey, {expiresIn: jwtExpirySeconds})
        req.token = token;
        next();
    } else {
        return res.status(400).send({message: 'Invalid credentials. Please login'})
    }
}

app.post('/login', authorization, (req, res) => {
    
    res.cookie('token', req.token, {maxAge: jwtExpirySeconds * 1000})
    res.send({status: 200,message: 'Login success'})

})

const authentication = (req, res, next) => {

    const token = req.cookies.token;
    if(!token) {
        return res.status(401).json({message: 'Token missing.'});
    }

    try {
        let payload = jwt.verify(token, jwtKey);
        if(payload) 
        req.body.payload = {userId: payload.userId}
        next();
        
    } catch (e) {
        if(e instanceof jwt.JsonWebTokenError) {
           return res.status(401).json({message: 'token error.'})
        }
        if(e instanceof jwt.TokenExpiredError) {
           return res.status(401).json({message: 'token expired.'})
        }
    }

}
app.get('/profile', authentication, (req, res) => {
    res.status(200).json({message: `Welcome to profile page ` + req.body.payload.userId})
} )

app.post('/logout', (req, res) => {
    res.cookie('token', null, {maxAge: 0})
    res.send({status: 200,message: 'logged out, cookies deleted.'})

})

app.listen(process.env.PORT, () => console.log(`Server is listening at port ${process.env.PORT}`));
