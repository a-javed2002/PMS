const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://user123:123@cluster0.hjjg8dd.mongodb.net/PMS', {useNewUrlParser: true, useCreateIndex: true,});
var conn =mongoose.Collection;

var userSchema =new mongoose.Schema({
    username: {type:String, 
        required: true,
        index: {
            unique: true,        
        }},
	email: {
        type:String, 
        required: true,
        index: {
            unique: true, 
        },},
    password: {
        type:String, 
        required: true
    },
    date:{
        type: Date, 
        default: Date.now }
});

var userModel = mongoose.model('users', userSchema);
module.exports=userModel;