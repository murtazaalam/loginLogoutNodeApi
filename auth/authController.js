const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const User = require('./userModel');

router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());
//Find().sort(createdAt[-1]) new data
//get all users
router.get('/users', (req, res) => {
    User.find({}, (err, users) => {
        if(err) throw err;
        res.send(users);
    })
})

//register users
router.post('/register', (req, res) => {
    var hashPassword = bcrypt.hashSync(req.body.password, 8);
    var email = req.body.email;
    console.log(req.body);
    User.find({email:email}, (err, data) => {
        if(data.length > 0){
            res.status(400).send({auth:false, token:'Email Already Taken.'})
        }
        else{
            User.create({
                name:req.body.name,
                email:req.body.email,
                password:hashPassword,
                phone:req.body.phone,
                role:req.body.role?req.body.role:'User'
            }, (err, data) => {
                if(err) return res.status(500).send('Error While Restering.')
                res.status(200).send('Registration Successful')
            })
        }
    })
})

//login user
router.get('/login', (req, res) => {
    User.findOne({email:req.body.email}, (err, data) => {
        if(err) return res.status(500).send({auth:false, token:'Error While Login.'})
        if(!data) return res.status(500).send({auth:false, token:'No User Found.'})
        const passIsValid = bcrypt.compareSync(req.body.password, data.password)
        if(!passIsValid) return res.status(500).send({auth:false, token:'Invalid Password'})
        var token = jwt.sign({id:data._id}, config.secret, {expiresIn:86400})
        res.send({auth:true, token: token})
    })
})

//user profile
router.get('/user-info', (req, res) => {
    var token = req.headers['x-access-token']
    if(!token) return res.status(500).send({auth:false, token:'No Token Provided.'})
    jwt.verify(token, config.secret, (err, user) => {
        if(err) return res.status(500).send({auth:false, token:'Invalid Token.'})
        User.findById(user.id, (err, result) => {
            res.send(result)
        })
    })
})
module.exports = router;