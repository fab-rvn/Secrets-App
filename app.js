require('dotenv').config();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRound = 10;

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);


app.get("/", function(req, res) {
  res.render("home");
});

app.route("/register")
.get(function(req, res) {
  res.render("register");
})
.post(function(req, res) {
  bcrypt.hash(req.body.password, saltRound, function(err, hash) {
    const newUser = new User({
      email: req.body.email,
      password: hash
    })
    newUser.save(function(err) {
      if (err) {
        console.log(err)
      } else {
        res.render("secrets");
      }
    });
  });
})
;

app.route("/login")
.get(function(req, res) {
  res.render("login");
})
.post(function(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({email: username}, function(err, foundUser) {
    if (err) {
      console.log(err)
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if (result === true) {
            res.render("secrets");
          }
        }); 
      }
    }
  });
})
;

app.listen(3000, function() {
  console.log("Server listening on port 3000")
});