const Router = require('express');
const router = Router();
const bycryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('./../models/user');
const mongoose = require('mongoose');

router.get('/auth/sign-up', (req, res, next) => {
  res.render('./../views/auth/sign-up.hbs');
});

//check for uniqueness of user name
//hash password
router.post('/profile', (req, res, next) => {
  const { userName, password } = req.body;
  console.log(userName);
  //check if userName is unique
  User.findOne({
    userName: userName
  })
    .then((user) => {
      console.log(user);
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

module.exports = router;
