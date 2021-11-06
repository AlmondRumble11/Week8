var express = require('express');
var router = express.Router();
const mongoose = require("mongoose");
const Users = require("../models/Users");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");


/* GET users listing. */
router.get('/', function(req, res, next) {
    res.send('respond with a resource');
});

//register new user
router.post('/api/user/register', /*body('username').isLenght({ min: 1 }).trim().escape(), body('password').isLenght({ min: 1 })*/ (req, res, next) => {
    if (body('email').isLenght < 1) {
        return res.send("need user name");
    }
    if (body('password').isLenght < 1) {
        return res.send("give password");
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
                    }).save((err, successful) => {
                        //if not successfull create the new user
                        if (err) throw err;
                        //if successful return 'ok'
                        return res.send('ok');

                    });
                });
            });
        }
    });
});


//login using user 
router.post('/users/login', (req, res, next) => {

});


module.exports = router;