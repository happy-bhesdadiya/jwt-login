const jwt = require('jsonwebtoken');
const Employee = require('../models/Employee');

const employeeAuthMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies.employee; // Here employee is the cookie name which is stores in browser
        const verifyEmployee = jwt.verify(token, process.env.TOKEN_SECRET_KEY);
        // console.log(verifyEmployee);

        const employee = await Employee.findOne({ _id:verifyEmployee._id })
        // console.log(employee);

        // For Logout
        req.token = token;
        req.employee = employee;

        next();
    } catch (error) {
        res.status(401).redirect('/signin');
    }    
}
  
module.exports = employeeAuthMiddleware
