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
const { body, validationResult } = require('express-validator');


/* GET users listing. */
router.get('/', function(req, res, next) {
    res.send('respond with a resource');
});
router.get('/api/user/register', (req, res, next) => {
    res.send('/api/user/register page')
});
//register new user
const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
router.post('/api/user/register',
    body('email').isEmail(),
    body("password").isLength({ min: 8 }),
    //https://github.com/express-validator/express-validator/issues/486 how to check using express-validator
    body('password').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9])/, 'i'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        Users.findOne({ email: req.body.email }, (err, user) => {
            if (err) throw err;

            //if has user already
            if (user) {
                return res.status(403).json({ email: "Email already in use." });
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
                        return res.send('ok');
                    });
                });
            }
        });
    });
//login using user 
router.post('/api/user/login', (req, res, next) => {

    //find the user
    Users.findOne({ email: req.body.email }, (err, user) => {
        //discard error
        if (err) throw err;

        //no user by that email
        if (!user) {
            return res.status(403).json({ success: false, msg: "No user found by that email" });
        }

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

                res.json({ success: true, token: token });
            }
        });
    });
});

//private route if logged in
router.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    //const token = authToken(req);
    return res.json({ email: req.user.email });

});

router.post('/api/todos', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    const user_id = req.user._id
    console.log(req.body);
    console.log(req.user);
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

module.exports = router;