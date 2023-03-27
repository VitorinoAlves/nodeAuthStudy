//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require("passport-local").Strategy;


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1:27017/userDB').then(()=>console.log('Databade Connected!'));

const userSchema= new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

const User = mongoose.model("User", userSchema);

passport.use(new LocalStrategy(
    function(username, password, done) {

        User.findOne({ username: username }).then(user =>{
            if (!user) {
                return done(null, false, {
                  message: "Incorrect Username"
                })
            }
            bcrypt.compare(password, user.password).then((isMatch) => {
                if (isMatch) {
                  return done(null, user)
                } else {
                  return done(null, false, {
                    message: "Incorrect Password"
                  })
                }
              }).catch((err) => {
                return done(err)
              });
        }).catch((err) => {
            return done(err)
        });
    }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    try {
        User.findById(id).then(user=>{
            done(null,user);
        })
    }
    catch (err){
        done(err);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
        console.log(profile);
        // Find or create user in your database
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          // Create new user in database
          const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
          const newUser = new User({
            username: profile.displayName,
            googleId: profile.id
          });
          user = await newUser.save();
        }
        return done(null, user);
      } catch (err) {
        return done(err);
    }
  }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] 
}));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}).then(users =>{
        if(users){
            res.render("secrets", {usersWithSecrets:users});
        }
    }).catch((err) => {
        console.log(err)
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
      } else {
        res.redirect("/login");
      }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id).then(user=>{
        if(user){
            user.secret = submittedSecret;
            user.save().then(function(){
                res.redirect("/secrets");
            })
        }
    })
});

app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});


app.post("/register", function(req, res){

    bcrypt.hash(req.body.password, 10, function(err, hash) { // 10 is SaltRounds
        if (err) {
          console.log(err);
        }
        const user = new User({
          username: req.body.username,
          password: hash
        })
        user.save();
        passport.authenticate('local')(req, res, () => {
          res.redirect("/secrets");
        })
    });
});

app.post('/login', 
  passport.authenticate('local', { 
    failureRedirect: '/login',  
    successRedirect: "/secrets"
}));

app.listen(3000, function(){
    console.log("Server started on port 3000");
})