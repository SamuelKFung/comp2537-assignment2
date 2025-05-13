require("./utils.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const url = require('url');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; // 1 hour in milliseconds

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/dne"},
    {name: "Login", link: "/login"},
    {name: "Signup", link: "/signup"},
]

app.use("/", (req, res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

app.set('view engine', 'ejs');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if(req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if(isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if(req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if(!isAdmin(req)) {
        res.status(403);
        res.render('errorMessage', {error: 'Not Authorized'});
        return;
    } else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render('index', { username: req.session.username});
});

app.get('/signup', (req, res) => {
    res.render('signUp');
});

app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({name, email, password}, {abortEarly: false});

    if(validationResult.error != null) {
        const errorMessages = [];

        console.log(validationResult.error);

        validationResult.error.details.forEach(err => {
            if (err.message.includes('name')) {
                errorMessages.push('Name is required');
            };

            if (err.message.includes('email')) {
                errorMessages.push('Email is required');
            };

            if (err.message.includes('password')) {
                errorMessages.push('Password is required');
            };
        });

        res.render('signUpSubmit', {errorMessages: errorMessages});
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: "user"
    });

    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });

	if(validationResult.error != null) {
        console.log(validationResult.error);
        res.render('loginSubmit');
        return;
	}

	const result = await userCollection
        .find({email: email})
        .project({name: 1, email: 1, password: 1, user_type: 1, _id: 1})
        .toArray();

	if(result.length != 1) {
        console.log("user not found");
		res.render('loginSubmit');
        return;
	}

	if(await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result[0].name;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
	}
	else {
		console.log("incorrect password");
		res.render('loginSubmit');
	}
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection
        .find()
        .project({name: 1, email: 1, password: 1, user_type: 1, _id: 1})
        .toArray();
    res.render('admin', {users: result});
});

app.get('/members', (req, res) => {
    if(!isValidSession(req)) {
        res.redirect('/');
        return;
    }

    res.render('members', {username: req.session.username});
});

app.post('/update-role/:role', async (req, res) => {
    const username = req.body.username;
    const role = req.params.role;
    
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        role: Joi.string().valid('admin', 'user').required()
    });

    const validationResult = schema.validate({ username, role });

    if(validationResult.error != null) {
        console.log(validationResult.error);
        return;
    }

    await userCollection.updateOne(
        {name: username},
        {$set: {user_type: role}
    });

    res.redirect('/admin');
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.use(function (req, res) {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 