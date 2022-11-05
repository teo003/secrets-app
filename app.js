//jshint esversion:6

// ----The order in all the code is very important prease maintain!------

//-----------require modules------------
require('dotenv').config(); //must be on top of code
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

//-----------create new app instant using express------------
const app = express();

//-----set view engine to use EJS as templating engine------------
app.set('view engine', 'ejs');

//-----------use body-parser to parse requests------------
app.use(bodyParser.urlencoded({
  extended: true
}));

//---use public directory to store static files such as images------------
app.use(express.static("public"));

//------------set up express-session-------------
app.use(session({
  secret: "Our secret.",
  resave: false,
  saveUninitialized: false //,
  //cookie: { secure: true }
}));

//----------set up passport------------
app.use(passport.initialize());
app.use(passport.session());

//----------set up mongodb-----------
mongoose.connect("mongodb://localhost:27017/process.env.DB_NAME", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose); //---------set up passportLocalMongoose-------
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

//-----passport configuration-----
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

//---passport google configuration-----
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets" //,
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

//-----------render home page--------------
app.route("/")

  .get(function(req, res) {
    res.render("home");
  });

//-----render the page for google authentication-------
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

//-----render the page accessed after google authentication-------
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

//-----------login page--------------
app.route("/login")

  .get(function(req, res) {
    res.render("login");
  })

  .post(function(req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    })

  });

//-----------register page--------------
app.route("/register")

  .get(function(req, res) {
    res.render("register");
  })

  .post(function(req, res) {
    User.register({
      username: req.body.username
    }, req.body.password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    });
  });
//-----------render home page--------------
app.route("/logout")

  .get(function(req, res) {
    req.logout(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.redirect("/");
      }
    });
  });

//-----------secrets page--------------
app.route("/secrets")

  .get(function(req, res) {
        //The line below means find all secret fields in DB that are NOT NULL
    User.find({"secret":{$ne: null}}, function(err, foundUsers){
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  });

//-----------submit page----------
app.route("/submit")

.get(function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

.post(function(req, res){
  const submittedSecret = req.body.secret;

  //console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

//-----------set up app to listen on port 3000------------
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
