const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const crypto = require('crypto');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

const conn = process.env.MONGO_URI;

const connection = mongoose.createConnection(conn, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const UserSchema = new mongoose.Schema({
  username: String,
  hash: String,
  salt: String
});

const User = connection.model('User', UserSchema);

passport.use(new LocalStrategy(
  function(username, password, cb) {
    User.findOne({ username: username })
      .then((user) => {
        if (!user) { return cb(null, false) }

        const isValid = validPassword(password, user.hash, user.salt);

        if (isValid) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      })
      .catch((err) => {
        cb(err);
      });
  }));


passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  User.findById(id, function (err, user) {
    if (err) { return cb(err); }
    cb(null, user);
  });
});

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: conn }),
  cookie: {
    maxAge: 1000 * 30
  }
}));

app.use(passport.initialize());
app.use(passport.session());


app.get('/', (req, res, next) => {
  res.send('<h1>Home</h1>');
});

app.get('/login', (req, res, next) => {

  const form = '<h1>Login Page</h1><form method="POST" action="/login">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';
  res.send(form);
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure', successRedirect: 'login-success' }), (err, req, res, next) => {
  if (err) next(err);
});

app.get('/register', (req, res, next) => {
  const form = '<h1>Register Page</h1><form method="post" action="register">\
                    Enter Username:<br><input type="text" name="username">\
                    <br>Enter Password:<br><input type="password" name="password">\
                    <br><br><input type="submit" value="Submit"></form>';
  res.send(form);

});

app.post('/register', (req, res, next) => {
  const saltHash = genPassword(req.body.password);

  const salt = saltHash.salt;
  const hash = saltHash.hash;

  const newUser = new User({
    username: req.body.username,
    hash: hash,
    salt: salt
  });

  newUser.save()
    .then((user) => {
      console.log(user);
    });

  res.redirect('/login');
});

app.get('/protected-route', (req, res, next) => {
  console.log(req.session);
  console.log(req.user);

  if (req.isAuthenticated()) {
    res.send('<h1>You are authenticated</h1>');
  } else {
    res.send('<h1>You are not authenticated</h1>');
  }
});

app.get('/logout', (req, res, next) => {
  req.logout();
  res.redirect('/login');
});

app.get('/login-success', (req, res, next) => {
  console.log(req.session);
  res.send('You successfully logged in.');
});

app.get('/login-failure', (req, res, next) => {
  res.send('You entered the wrong password.');
});

app.listen(3000, () => {
  console.log('Server was started');
});


function validPassword(password, hash, salt) {
  const hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === hashVerify;
}

function genPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

  return {
    salt: salt,
    hash: genHash
  };
}
