var express = require('express');
var router = express.Router();
const mongoose = require("mongoose");
const Users = require("../models/Users");
const Todo = require("../models/Todo");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const passport = require('passport');
const authToken = require("../auth/auth.js")
const multer = require("multer")
const storage = multer.memoryStorage();
const upload = multer({ storage })


const { body, validationResult } = require('express-validator');


router.get('/register.html', (req, res, next) => {
    res.render('register');
});
router.get('/login.html', (req, res, next) => {
    res.render('login');
});

router.get(('/'), (req, res, next) => {
    res.render('index');
});



/* GET users listing. */
router.get('/', function(req, res, next) {
    res.send('MAIN PAGE');
});
router.get('/api/users/register', (req, res, next) => {
    res.send('/api/user/register page')
});
//register new user
const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
router.post('/users/register',
    body('email').isEmail(),
    body("password").isLength({ min: 8 }),
    //https://github.com/express-validator/express-validator/issues/486 how to check using express-validator
    body('password').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9])/, 'i'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            for (let i = 0; i < errors.array().length; i++) {
                if (errors.array()[i].param == "password") {
                    return res.status(403).send("Password is not strong enough");
                }
            }
            return res.status(400).json({ errors: errors.array() });
        }
        Users.findOne({ email: req.body.email }, (err, user) => {
            if (err) throw err;

            //if has user already
            if (user) {
                return res.status(403).send("Email already in use");
                //if no user-> create one
            } else {
                //using brcypt to crypt the passaword
                bcrypt.genSalt(10, (err, salt) => {
                    //cryptes the password
                    bcrypt.hash(req.body.password, salt, (err, crypted_password) => {
                        //if error --> discard it
                        if (err) throw err;
                        //create new user with the crypted password
                        Users.create({
                            email: req.body.email,
                            password: crypted_password
                        });
                        console.log("account createad");
                        return res.redirect("/login.html");
                    });
                });
            }
        });
    });
//login using user 
router.post('/users/login', upload.none(), (req, res, next) => {

    //find the user
    console.log("finding user:" + req.body.email);
    console.log("finding password:" + req.body.password);
    Users.findOne({ email: req.body.email }, (err, user) => {
        //discard error
        console.log(user);
        if (err) throw err;

        //no user by that email
        if (!user) {

            return res.status(403).send({ success: false, msg: "Invalid credentials" });
        } else {

            //check the password using brycpt
            bcrypt.compare(req.body.password, user.password, (err, matches) => {
                //discard error
                if (err) throw err;

                //if the passwords are the same
                if (matches) {
                    //create jwt token 
                    const jwtPayload = {
                        email: user.email,
                    };
                    console.log(process.env.SECRET);
                    //secret is from the .env file 
                    var token = jwt.sign(
                        jwtPayload,
                        process.env.SECRET, {
                            expiresIn: 10000
                        });

                    //return res.redirect('/');
                    res.json({ success: true, token: token, msg: 'Logged in' });
                } else {
                    res.send({ success: false, token: token, msg: 'Invalid credentials' });
                }
            });
        }
    });
});

//private route if logged in
router.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    //const token = authToken(req);
    return res.json({ email: req.user.email });

});

router.post('/api/todos', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    const user_id = req.user._id
    console.log("body is " + req.body.items);
    //console.log(req.user);
    Todo.findOne({ user: user_id }, (err, data) => {
        if (err) throw err;
        console.log("data from the todo:" + data);
        if (!data) {
            console.log("no data. creating new todo");
            Todo.create({
                user: req.user._id,
                items: req.body.items

            });
            return res.send('ok');
        } else {
            console.log("had data. updating...");
            var newItems = req.body.items;
            const todoID = data._id;

            //https://www.codegrepper.com/code-examples/javascript/add+in+to+array+mongoose
            //how to append data to mongo
            Todo.findOneAndUpdate({ _id: todoID }, { $push: { items: newItems } },
                (error, success) => {
                    if (error) {
                        console.log(error);
                    } else {
                        console.log(success);
                    }
                });
            return res.send('ok');
        }
    })
});

router.get('/api/todos', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    const user_id = req.user._id
    console.log("body is " + req.body.items);
    //console.log(req.user);
    Todo.findOne({ user: user_id }, (err, data) => {
        if (err) throw err;
        console.log("data from the todo:" + data);
        if (!data) {

            return res.json({ msg: 'no data' });
        } else {
            console.log("had data. updating...");

            const todoID = data._id;

            //https://www.codegrepper.com/code-examples/javascript/add+in+to+array+mongoose
            //how to append data to mongo
            Todo.find({ _id: todoID }, (err, data) => {
                if (err) {
                    console.log(err);
                } else {
                    console.log(data);
                }
            });
            return res.json(data);
        }
    })
});

module.exports = router;