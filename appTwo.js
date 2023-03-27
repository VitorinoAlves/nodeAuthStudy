require("dotenv").config();
const express = require("express");
const app = express();
const ejs = require("ejs");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
app.use(express.urlencoded({
  extended: false
})); // Not using bodyParser, using Express in-built body parser instead
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://127.0.0.1:27017/userDB");
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  secret: String
});
const User = new mongoose.model("User", userSchema);
// Creating Local Strategy. passport-local-mongoose 3 lines of code for Strategy,
// Serialiazation, Deserialization not working due to recent changes in Mongoose 7
passport.use(new LocalStrategy((username, password, done) => { //done is a callback function
  User.findOne({
    username: username
  }).then(user => {
    if (!user) {
      return done(null, false, {
        message: "Incorrect Username"
      })
    }
    // using bcrypt to encrypt password in register post route and compare function in login post round.
    // login post route will check here during authentication so need to use compare here
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
}));
// serialize user
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
// deserialize user
passport.deserializeUser(function(id, done) {
  User.findById(id).then(user => {
    done(null, user);
  }).catch((err) => {
    return done(err)
  });
});
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/secrets'
}, async function(accessToken, refreshToken, profile, done) {
  try {
    console.log(profile);
    // Find or create user in your database
    let user = await User.findOne({
      googleId: profile.id
    });
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
}));
//get routes
app.get("/", function(req, res) {
  res.render("home");
});
app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets", function(req, res) {
  User.find({
    secret: {
      $ne: null
    }
  }).then((foundUsers) => {
    res.render("secrets", {
      usersWithSecrets: foundUsers
    })
  }).catch((err) => {
    console.log(err)
  });
});
app.get("/logout", function(req, res) {
  req.logout(function(err) {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
});
app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile"]
}));
app.get("/auth/google/secrets", passport.authenticate("google", {
  failureRedirect: "/login"
}), function(req, res) {
  // Successful authentication, redirect home.
  res.redirect("/secrets");
});
app.route("/submit").get(function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.rediret("/login");
  }
}).post(function(req, res) {
    const submittedsecret = req.body.secret;
    User.findById(req.user.id).then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedsecret;
        foundUser.save().then(() => {
          res.redirect("/secrets")
        }).catch((err) => {
          console.log(err)
        });
      }
    }).catch((err) => {
      console.log(err)
    });
  });
  // post routes
  app.post("/register", function(req, res) {
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
    })
  });
  app.post('/login', passport.authenticate('local', {
    successRedirect: "/secrets",
    failureRedirect: '/login'
  }));
  // listen
  app.listen(3000, () => {
    console.log("Server Running on Port 3000");
  });