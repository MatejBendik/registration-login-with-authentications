require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// Use session package
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

// Initiazing passport and use passport to manage sessions
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection to database and creating schema for collections and documents
mongoose.connect("mongodb://localhost:27017/userDB");

// Full mongoose Schema with some features in it. It's not just a basic JS object any more
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// This is plugin for hashing and salting passwords and to saving our users into mongodb database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// Here we used passport to create our local login strategy and set a passport to serialize and deserialize our user
passport.use(User.createStrategy());

passport.serializeUser(function (user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
    }
));

app.get("/",function(req,res){
    res.render("home");
});

// Authenticating user with Google 
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })          // Here we are telling google what we want is users profile
);

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
});

app.get("/login",function(req, res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

// Here we are gonna check if the user is logged in/registered in or not
app.get("/secrets",function(req, res){
// look through collection and find all the places where the secret field is not equal to null
User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
        console.log(err);
    } else {
        if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    }
    });
});

app.get("/submit",function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{                                  
        res.redirect("/login");
    }
});

app.post("/register",function(req,res){
// Here we are registering user with provided data from the form
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){                            // If there were any errors we will redirect them back to the register page to try again
            console.log(err);
            res.redirect("/register");
        }else{                              // If there were no errors we going to authenticate the user using passport and successfully set up a cookie with current log in session 
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })

});

app.post('/logout', function(req, res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect("/");
        }
    });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){        // this will search through the db and finds user by id from req variable
        if(err){
            console.log(err);
        }else{
            if(foundUser){                                      // if user is found, then add his text - secret to his name (secret will now have value) in db
                foundUser.secret = submittedSecret;
                foundUser.save(function(){                      // after saving it into db, redirect the user to /secrets route so he can see his secret with others.
                    res.redirect("/secrets");
                });
            }
        }
    })
});

app.listen(3000, function(){
    console.log('Server started on port 3000.');
});