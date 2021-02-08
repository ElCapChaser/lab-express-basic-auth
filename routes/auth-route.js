const Router = require('express');
const router = Router();
const bycryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('./../models/user');
const mongoose = require('mongoose');

//SING-UP ROUTES
router.get('/sign-up', (req, res, next) => {
  res.render('./../views/auth/sign-up.hbs');
});

//check for uniqueness of user name
//hash password
router.post('/sign-up', (req, res, next) => {
  const { userName, password } = req.body;
  //check if userName is unique
  User.findOne({
    userName: userName
  })
    .then((user) => {
      if (user) {
        throw new Error('There is already a user with that username.');
      } else {
        return bycryptjs
          .genSalt(saltRounds)
          .then((salt) => bycryptjs.hash(password, salt));
      }
    })
    .then((hashedPassword) => {
      return User.create({
        userName,
        passwordHash: hashedPassword
      });
    })
    .then(() => {
      res.render('./../views/auth/sign-up.hbs');
    })
    .catch((error) => next(error));
});

//LOG IN ROUTES

router.get('/log-in', (req, res, next) => {
  res.render('./../views/auth/log-in.hbs');
});

router.post('/log-in', (req, res, next) => {
  const { userName, password } = req.body;
  //look-up user to check if it exsists
  User.findOne({ userName })
    .then((user) => {
      if (!user) {
        res.render('auth/log-in', { errorMessage: 'User doesnt exist' });
      } else if (bycryptjs.compareSync(password, user.passwordHash)) {
        //set the session
        req.session.currentUser = user;
        res.redirect('/userProfile');
      } else {
        res.render('auth/log-in', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch((error) => next(error));
});

router.post('/logout', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;
