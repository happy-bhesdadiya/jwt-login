const jwt = require('jsonwebtoken');
const Employee = require('../models/Employee');
const NodeRSA = require('node-rsa');
const key = new NodeRSA({b: 1024});
const Cryptr = require('cryptr');
const cryptr = new Cryptr('myTotalySecretKey');

const employeeAuthMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies.employee; // Here employee is the cookie name which is stores in browser
        // console.log(token);

        // const encrypted_token = key.encrypt(token, 'base64');
        // console.log('encrypted 2: ', encrypted_token);

        // const decrypted_token = key.decrypt(token, 'utf8');
        // console.log('decrypted 2: ', decrypted_token);

        const decryptedString = cryptr.decrypt(token);
        // console.log(`decrypted : ${decryptedString}`);

        const verifyEmployee = jwt.verify(decryptedString, process.env.TOKEN_SECRET_KEY);
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
