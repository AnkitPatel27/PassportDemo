const fs = require("fs")
require('dotenv').config()
const path = require("path")
const https = require("https")
const helmet = require("helmet")
const express = require("express")
const { serialize } = require("v8")
const passport = require("passport")
var cookieSession = require('cookie-session')
var GoogleStrategy = require('passport-google-oauth20').Strategy;

const verifyCb = function (accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    console.log("verify")
    return cb(null, profile)
    // User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //     return cb(err, user);
    // });
};

// save session to cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
})


// read the session from cookie to request
passport.deserializeUser((obj, done) => {
    done(null, obj);
})

const app = express()

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_SECRET_KEY,
    callbackURL: "https://localhost:8000/auth/google/callback"
},
    verifyCb
));




app.use(helmet());

//why use cookie session see on "https://www.passportjs.org/concepts/authentication/sessions/"
//Applications must initialize session support in order to make use of login sessions by. 
//In an Express app, session support is added by using express-session or cookie-session middleware
app.use(cookieSession({
    name: 'session',
    keys: ["YOYOANKIT"],
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))

app.use(function (request, response, next) {
    if (request.session && !request.session.regenerate) {
        request.session.regenerate = (cb) => {
            cb()
        }
    }
    if (request.session && !request.session.save) {
        request.session.save = (cb) => {
            cb()
        }
    }
    next()
})

app.use(passport.initialize());
app.use(passport.session());

const checkValidator = (req, res, next) => {
    console.log("checker ", req.user)
    const checkLogin = req.isAuthenticated() && req.user;
    if (!checkLogin) {
        console.log("login check failed");
        res.status(401).send('You are not authorized');
    }
    next();
}

app.get("/", (req, res) => {
    const options = {
        root: path.join(__dirname, "public")
    };
    res.sendFile('./index.html', options)
})

app.get('/Google/Login', passport.authenticate('google', { scope: ['profile'] }))

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', session: true }),
    function (req, res) {
        console.log(req);
        console.log("came to callback");
        res.redirect('/secret');
    });


app.get('/secret', checkValidator, (req, res) => {

    const options = {
        root: path.join(__dirname, "public")
    };
    res.sendFile('./secret.html', options)
})

app.get('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

https.createServer({
    key: fs.readFileSync('key.pem'), //key is a private key for asymmtric encryption
    cert: fs.readFileSync('cert.pem') //cert is a public key for asymmtric encryption
}, app).listen(8000)

//

//so inroder to establish a secure enrypted connection or session we first use asymmetric encryption to pass a common key which
//can be used further for encryption to pass this common key first we use asymmtric encryption allowing us to safely common key over internet
// this key is then used for further encryption
//So overly 1st we use asymmtric encryption to establish a secure session
// then after the session has been built we use symmtric encryption
