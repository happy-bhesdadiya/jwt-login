const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const Employee = require('../models/Employee');
const { validationResult } = require('express-validator');

module.exports.index_get = (req, res) => {
    const token = req.cookies.employee; // Here employee is the cookie name which is stores in browser
    const verifyEmployee = jwt.verify(token, process.env.TOKEN_SECRET_KEY);

    res.render('index', { verifyEmployee })
}

module.exports.signup_get = (req, res) => {
    res.render('signup')
}

module.exports.signup_post = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const alert = errors.array();
            res.render('signup', { alert });
        } else {
            const email = req.body.email;
            const password = req.body.password;
            const confirm_password = req.body.confirm_password;

            const checkEmail = await Employee.find({email: email}).countDocuments();

            if (checkEmail === 0) {
                if (password === confirm_password) {
                    const employee = new Employee({
                        name: req.body.name,
                        email: req.body.email,
                        password: req.body.password,
                        confirm_password: req.body.confirm_password
                    })

                    // for token generate and store in database
                    const token = await employee.generateEmployeeAuthToken();
                    // This is store in cookie browsers
                    res.cookie('employee', token, {
                        expires: new Date(Date.now() + (1000 * 60 * 60 * 24)),
                        httpOnly: true
                    })

                    // save data
                    await employee.save();

                    res.status(201).render('index');
                } else {
                    req.flash('error', 'Password not Match!');
                    res.render('signup', { error_message: req.flash('error') });
                }
            } else {
                req.flash('error', 'Email Already exists!');
                res.render('signup', { error_message: req.flash('error') });   
            }
        }
    } catch (err) {
        res.status(400).send(err)
    }
}

module.exports.signin_get = (req, res) => {
    res.render('signin')
}

module.exports.signin_post = async (req, res) => {
    try {
        const email = req.body.email;
        const password = req.body.password;
        const employee = await Employee.findOne({ email });
        const isMatch = await bcrypt.compare(password, employee.password)

        if (isMatch) {
            const token = await employee.generateEmployeeAuthToken();
            res.cookie('employee', token, {
                expires: new Date(Date.now() + (1000 * 60 * 60 * 24)),
                httpOnly: true
            })
            res.redirect('/');
        } else {
            req.flash('error', 'Email or Password Invalid');
            res.render('signin', { error_message: req.flash('error') });
        }
    } catch (err) {
        req.flash('error', 'Email or Password Invalid');
        res.render('signin', { error_message: req.flash('error') });
    }
}

module.exports.signout = async (req, res) => {
    try {
        // For single device
        req.employee.tokens = req.employee.tokens.filter((currToken) => {
            return currToken.token != req.token     // filter current token in database 
        })

        res.clearCookie('employee'); // It will clear cookie from browser
        await req.employee.save(); // Here req.employee is come from authMiddleware
        res.redirect('/signin');
    } catch (err) {
        res.status(500).send(error);   
    }
}

module.exports.signout_all = async (req, res) => {
    try {
        // For all devices
        req.employee.tokens = []; // Here req.employee is come from authMiddleware

        res.clearCookie('employee'); // It will clear cookie from browser
        await req.employee.save(); // Here req.employee is come from authMiddleware
        res.redirect('/signin');
    } catch (err) {
        res.status(500).send(error);   
    }
}

module.exports.forgot_password_get = (req, res) => {
    res.render('forgot_password')
}

module.exports.forgot_password_post = async (req, res) => {

}