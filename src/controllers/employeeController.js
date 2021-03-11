const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const Employee = require('../models/Employee');
const { validationResult } = require('express-validator');
const NodeRSA = require('node-rsa');
const key = new NodeRSA({b: 1024});
const mailgun = require("mailgun-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr('myTotalySecretKey');

module.exports.index_get = (req, res) => {
    const token = req.cookies.employee; // Here employee is the cookie name which is stores in browser
    const decryptedString = cryptr.decrypt(token);
    const verifyEmployee = jwt.verify(decryptedString, process.env.TOKEN_SECRET_KEY);

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

                    res.status(201).redirect('/');
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
            // console.log(token);

            // const encrypted_token = key.encrypt(token, 'base64');
            // console.log('encrypted 3: ', encrypted_token);

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
        res.status(500).send(err);   
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
        res.status(500).send(err);   
    }
}

module.exports.forgot_password_get = (req, res) => {
    res.render('forgot_password')
}

module.exports.forgot_password_post = async (req, res) => {
    try {
        const email = req.body.email
        const employee = await Employee.findOne({ email });
        const id = employee._id;
        if (employee) {

            const plain_token = jwt.sign({_id: employee._id}, process.env.JWT_FORGOT_PASS_KEY, {expiresIn: '5m'})
            
            const token = cryptr.encrypt(plain_token);

            employee.tokens = employee.tokens.concat({ token }) // Here token is token:token first is in field - second is variable so we write {token}
            await employee.save()

            const DOMAIN = "sandboxedfdc311bf814dde9b4017e4e010515b.mailgun.org";
            const mg = mailgun({apiKey: process.env.MAILGUN_APIKEY, domain: DOMAIN});
            const data = {
                from: "noreplay@happy.com",
                to: email,
                subject: "Forgot Password",
                html: `
                    <h2>Please click on given link to Reset your password</h2>
                    <a href="${process.env.CLIENT_URL}/reset-password/${id}/${token}">${process.env.CLIENT_URL}/reset-password/${id}/${token}</a>`
            };
            // mg.messages().send(data, function (error, body) {
            //     console.log(body);
            // });

            return employee.updateOne({resetLink: token}, function (err, success) {
                if (err) {
                    return res.status(400).json({error: 'Forgot Password error'})
                } else {
                    mg.messages().send(data, function (error, body) {
                        if (error) {
                            return res.send('Error while sending mail')
                        }
                        req.flash('success', 'Email send Successfull!');
                        res.render('forgot_password', { success_message: req.flash('success') });
                    });
                }
            })
            
        } else {
            req.flash('error', 'Email does not Exists!');
            res.render('forgot_password', { error_message: req.flash('error') });
        }
        

    } catch (err) {
        req.flash('error', 'Email does not Exists!');
        res.render('forgot_password', { error_message: req.flash('error') });
    }
}

module.exports.reset_password_get = async (req, res) => {
    try {
        const { id, token } = req.params;
        const decryptedString = cryptr.decrypt(token);
        const verifyEmployee = jwt.verify(decryptedString, process.env.JWT_FORGOT_PASS_KEY);
        const employee = await Employee.findOne({ 'tokens.token': token })
        // console.log(employee);
        
        if (employee) {
            res.render('reset_password', { id, token })
        } else {
            res.send('Token Expired!')
        }
    } catch (err) {
        res.send('Token Expired')
    }
}

module.exports.reset_password_post = async (req, res) => {
    try {
        const { id, token } = req.params;

        const password = req.body.password;
        const confirm_password = req.body.confirm_password;

        if (password === confirm_password) {
            req.body.password = await bcrypt.hash(req.body.password, 8);
            req.body.confirm_password = await bcrypt.hash(req.body.confirm_password, 8);
            const employee = await Employee.findOneAndUpdate({ _id: id }, req.body, { new: true }, async (err, doc) => {
                if (!err) {

                    doc.tokens = [];
                    await doc.save();
                    
                    req.flash('success', 'Password Reset Successfully');
                    res.render('reset_password', { id, token, success_message: req.flash('success') });
                } else {
                    req.flash('error', 'Error while reseting password');
                    res.render('reset_password', { error_message: req.flash('error') });
                }
            })
        } else {
            req.flash('error', 'Password does not Match!!');
            res.render('reset_password', { error_message: req.flash('error') });   
        }

    } catch (err) {
        res.status(500).send(err); 
    }
}