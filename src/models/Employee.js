const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const NodeRSA = require('node-rsa');
const key = new NodeRSA({b: 1024});
const Cryptr = require('cryptr');
const cryptr = new Cryptr('myTotalySecretKey');

const employeeSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    confirm_password: {
        type: String,
        required: true
    },
    resetLink: {
        data: String,
        default: ''
    },
    tokens: [{
        token: {
            type: String,
            required: true,
        }
    }]
})

// Generting token - This is a type of middleware
employeeSchema.methods.generateEmployeeAuthToken = async function() {
    try {
        const employee = this
        // here the secret key is minimum 32 character thisisloginregistrationforpractice
        const token = jwt.sign({_id: employee._id.toString()}, process.env.TOKEN_SECRET_KEY)
        // console.log(token);
        // const encrypted_token = key.encrypt(token, 'base64');
        // console.log('encrypted: ', encrypted_token);

        // const decrypted_token = key.decrypt(encrypted_token, 'utf8');
        // console.log('decrypted: ', decrypted_token);

        const encryptedString = cryptr.encrypt(token);
        // console.log(`encrypted : ${encryptedString}`);

        // const decryptedString = cryptr.decrypt(encryptedString);
        // console.log(`decrypted : ${decryptedString}`);

        employee.tokens = employee.tokens.concat({ token: encryptedString }) // Here token is token:token first is in field - second is variable so we write {token}
        await employee.save()

        // return token
        return encryptedString
    } catch (error) {
        console.log(error);
    }
}

// Hash the plain text password before saving using pre hook
employeeSchema.pre('save', async function (next) {
    const employee = this
  
    if (employee.isModified('password')) {
        employee.password = await bcrypt.hash(employee.password, 8)
    }
    if (employee.isModified('confirm_password')) {
        employee.confirm_password = await bcrypt.hash(employee.confirm_password, 8)
    }
    
    next()
  })

const Employee = new mongoose.model('Employee', employeeSchema);

module.exports = Employee