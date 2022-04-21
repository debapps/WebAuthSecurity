//Get all required package.
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

//Post to connect the application.
const port = process.env.PORT || 3000;

//Creating the express application.
const app = express();

//Using Body Parser to parse the HTML form input values.
app.use(bodyParser.urlencoded({ extended: true }));

//Setting the static folder for CSS.
app.use(express.static("public"));

//Setting the view engine with EJS.
app.set("view engine", "ejs");

//Setting up the session.
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

//Initializing passport and use the session.
app.use(passport.initialize());
app.use(passport.session());

//MongoDB URL.
const mongoURL = "mongodb://localhost:27017/userDB";

//Connecting to MongoDB.
mongoose.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false });

//Creating the userDB schema.
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secretText: String
});

//Plug-in the passport-local-mongoose with mongoDB schema.
userSchema.plugin(passportLocalMongoose);

//Plug-in findOrCreate with mongoDB schema.
userSchema.plugin(findOrCreate);

//Creating the User model.
const User = mongoose.model("User", userSchema);

//Setting up user login strategy as local.
passport.use(User.createStrategy());

//Serialize and De-serialize the user.
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

//Setting up the Google OAuth 2.0 authentication strategy.
passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));

//Setting up the Facebook OAuth authentication strategy.
passport.use(new FacebookStrategy({
        clientID: process.env.FB_APP_ID,
        clientSecret: process.env.FB_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));

//The Home ("/") route.
app.route("/")

//HTTP GET Request on Home ("/") route
.get(function(req, res) {
    res.render("home");
});

//The Login ("/login") route.
app.route("/login")

//HTTP GET request on the Login ("/login") route.
.get(function(req, res) {
    res.render("login");
})

//HTTP POST request on the Login ("/login") route.
.post(function(req, res) {
    //Getting the new user credential from the login page.
    let userCredentials = new User({
        username: req.body.username,
        password: req.body.password
    });

    //Login useing input credentials.
    req.login(userCredentials, function(error) {
        if (error) {
            console.log(error);
            res.redirect("/");
        } else {
            //Authenticate the user as per userDB.
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

//HTTP GET Request on Logout ("/logout") Route
app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

//The Register ("/register") route.
app.route("/register")

//HTTP GET request on the Register ("/register") route.
.get(function(req, res) {
    res.render("register");
})

//HTTP POST request on the Register ("/register") route.
.post(function(req, res) {
    //Register the new username and password into userDB.
    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            //Authenticate the new user as per userDB.
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

//The Secrets ("/secrets") route.
app.route("/secrets")

//HTTP GET Request on the Secrets ("/secrets") route.
.get(function(req, res) {
    if (req.isAuthenticated()) {
        //Find all the user data from the userDB who has a secret text.
        User.find({ secretText: { $ne: null } }, function(error, foundUsers) {
            if (error) {
                console.log(error);
            } else {
                if (foundUsers) {
                    res.render("secrets", { usersWithSecret: foundUsers });
                }
            }
        });
    } else {
        res.redirect("/login");
    }
});

//The Submit ("/submit") route.
app.route("/submit")

//HTTP GET Request on the Submit ("/submit") route.
.get(function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

//HTTP POST Request on the Submit ("/submit") route.
.post(function(req, res) {
    //Get the secret message.
    let secretMessage = req.body.secret;

    //Find the user by ID and update the secret text.
    User.findByIdAndUpdate(req.user.id, { secretText: secretMessage }, function(error) {
        if (error) {
            console.log(error);
        } else {
            res.redirect("/secrets");
        }
    });

});

//HTTP GET Requests for Google OAuth 2.0.
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect secret page.
        res.redirect("/secrets");
    });

//HTTP GET Requests for Facebook OAuth.
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets", passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });


//Starting the server at port.
app.listen(port, function() {
    console.log("Server has started at port - " + port);
});