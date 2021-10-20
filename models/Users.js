//get mongoose
const mongoose = require("mongoose");

//get schema
const Schema = mongoose.Schema;

//tells what is inside the db collection
let usersShema = new Schema({
    email: String,
    password: String,
});

module.exports = mongoose.model("Users", usersShema);