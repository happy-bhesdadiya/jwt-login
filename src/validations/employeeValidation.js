const { check } = require('express-validator');

module.exports.employeeAuth_validation = [
    check('name', 'Name must be minimum 2 character').exists().isLength({ min: 2 }),
    check('email', 'Email is not valid').isEmail().normalizeEmail()
];