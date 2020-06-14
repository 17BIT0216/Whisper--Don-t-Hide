//jshint esversion:6c
require('dotenv').config()
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
// const md5=require("md5");
// const bcrypt=require("bcrypt");
// const saltRounds=10;
const session = require('express-session');
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");



const app=express();

app.use(express.static("public"));
app.set('view engine','ejs'); //where ejs files will be present
app.use(bodyParser.urlencoded({extended:true}));

//this must me admitedly be here
app.use(session({
  secret: 'I Love my Country',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/AuthenticDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  name:String,
  password:String,
  googleId:String,//so it can have a unique google id with which it can be found again
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt,{secret:process.env.YESECRET, excludeFromEncryption: ['name']});
//so when ever the username is saved it is encrypted first
//and when we try to find the password it is automatically decrypted

const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy()); //this refers to the strategy we used

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENTID,
    clientSecret: process.env.CLIENTSECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",

  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    //here it deals with local storage if it is found in the database then okay other wise it is created
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/",function(req,res)
{
  res.render("home");
});

app.get("/login",function(req,res)
{
  res.render("login");
});

app.get("/register",function(req,res)
{
  res.render("register");
});

app.get("/secrets",function(req,res)
{
  //now here we authenticate our user with his session
  if(req.isAuthenticated())   //if the request is authentic
  res.render("secrets");
  else
  res.redirect("/login");
})

//here we serve the get request of the buttons and authenticate using google
app.get('/auth/google',
  passport.authenticate("google", { scope: ["profile"] }));

//then google will redirect to this url so we have to serve it
  app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      //if fails then redirected to the login page
      res.redirect('/secrets');
    });



//This works for local
app.post("/register",function(req,res)
{
  //here the variable names are fixed has tobe username and password
User.register({username:req.body.username},req.body.password,function(err,result)
{
  if(err)
  {
  res.redirect("/register");
}
  else{
  passport.authenticate("local")(req,res,function(){
  res.redirect("/secrets"); //now the case here is the user can go directely to the secrets
});
}
})
});

app.get("/logout",function(req,res)
{
  req.logout();
  res.redirect('/register');
})


app.post("/login",function(req,res)
{
const newUser= new User(
  {
    name:req.body.username,
    password:req.body.password,
  }
);

req.login(newUser,function(err)
{
  if(err)
  {
  res.redirect("/login");
}
  else
  {
    //if no errors then we authenticate the user and give him a cookie so that he may be rememberred
    passport.authenticate("local")(req,res,function(){
    res.redirect("/secrets");
  });
}


});
});


app.listen(3000,function(req,res)
{
  console.log("Listening");
})
