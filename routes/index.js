const { Router } = require('express');
const router = Router();

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/userProfile', (req, res, next) => {
  res.render('userProfile', { userInSession: req.session.currentUser });
});


module.exports = router;
