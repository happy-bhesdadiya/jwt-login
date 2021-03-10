const express = require('express');
const router = express.Router();

const employeeController = require('../controllers/employeeController');
const employeeValidation = require('../validations/employeeValidation');
const employeeAuthMiddleware = require('../middleware/employeeAuthMiddleware');

router.get('/', employeeAuthMiddleware, employeeController.index_get);

router.get('/signup', employeeController.signup_get);
router.post('/signup', employeeValidation.employeeAuth_validation, employeeController.signup_post);

router.get('/signin', employeeController.signin_get);
router.post('/signin', employeeController.signin_post);

router.get('/signout', employeeAuthMiddleware, employeeController.signout);
router.get('/signout-all', employeeAuthMiddleware, employeeController.signout_all);

router.get('/forgot-password', employeeController.forgot_password_get);

module.exports = router