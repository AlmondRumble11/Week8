const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const Users = require('../models/Users');
const passport = require("passport");



module.exports = function(req) {
    let opts = {};
    opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
    opts.secretOrKey = process.env.SECRET;

    console.log(opts);
    console.log("passport use");
    passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
        console.log(jwt_payload);
        Users.findOne({ email: jwt_payload.email }, (err, user) => {
            if (err) {
                return done(err, false);
            }

            if (user) {

                return done(null, user);
            } else {
                return done(null, false);
            }
        });
    }));

}