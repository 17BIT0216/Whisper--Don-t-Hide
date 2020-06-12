//jshint esversion:6c
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");

const app=express();

app.use(express.static("public"));
app.set('view engine','ejs'); //where ejs files will be present
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect('mongodb://localhost:27017/AuthenticDB', {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = {
  name:String,
  password:String,
}

const User=new mongoose.model("User",userSchema);


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

app.post("/register",function(req,res)
{
  const user=new User(
    {name:req.body.username,
      password:req.body.password,
    });
    //created a new user
    user.save(function(err)
  {
    if(!err)
    {
      res.render("secrets");
    }
  });
  })

app.post("/login",function(req,res)
{
  const username=req.body.username;
  const password=req.body.password;
  User.findOne({name:username},function(err,foundArticle)
{
if(err)
{
  console.log(err);
}
else
{
  if(foundArticle)
  {
    if(foundArticle.password===password)
    res.render("secrets");
  }
}
})

})





app.listen(3000,function(req,res)
{
  console.log("Listening");
})
