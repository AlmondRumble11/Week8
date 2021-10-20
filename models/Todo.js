//get mongoose
const mongoose = require("mongoose");

//get schema
const Schema = mongoose.Schema;

//tells what is inside the db collection
let todoShema = new Schema({
    user: String,
    items: Array,
});

module.exports = mongoose.model("Todo", todoShema);