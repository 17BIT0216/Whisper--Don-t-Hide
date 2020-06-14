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
})

userSchema.plugin(passportLocalMongoose);

//userSchema.plugin(encrypt,{secret:process.env.YESECRET, excludeFromEncryption: ['name']});
//so when ever the username is saved it is encrypted first
//and when we try to find the password it is automatically decrypted

const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy()); //this refers to the strategy we used

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser()); //serializes and stores the data
passport.deserializeUser(User.deserializeUser());//deserializes and displays the data

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


app.post("/register",function(req,res)
{
  //here the variable names are fixed has tobe username and password
User.register({username:req.body.username},req.body.password,function(err,result)
{
  if(err)
  {
    console.log(result);
    console.log(err);
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
