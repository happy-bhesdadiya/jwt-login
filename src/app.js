require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const flash = require('connect-flash');
const bodyParser = require('body-parser');
require('./db/conn');

const employeeRouter = require('./routes/employeeRoute');

const app = express();

const port = process.env.PORT

app.use(express.json());
app.use(express.urlencoded({extended: false }));

app.use(cookieParser());

app.use(session({ secret: 'secretsession', cookie: { maxAge: 60000 }, resave: false, saveUninitialized: false }));
app.use(flash());

app.set('view engine', 'ejs');

app.locals.success_message = ''
app.locals.error_message = ''
app.locals.verifyEmployee = ''

app.use(employeeRouter);

app.listen(port, () => {
    console.log(`Server is running at ${port}`);
})