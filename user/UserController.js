var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var VerifyToken = require(__root + 'auth/VerifyToken');

router.use(bodyParser.urlencoded({ extended: true }));
var User = require('./User');

// CREATES A NEW USER
router.post('/', function (req, res) {
	User.create({
            name : req.body.name,
            email : req.body.email,
            password : req.body.password
        }).then((result) => {
  		return res.status(200).send(result)
	}).catch((err) => {
  		return res.status(500).send("there was a problem adding info to the DB")
        })
});

// RETURNS ALL THE USERS IN THE DATABASE
router.get('/',  VerifyToken, function (req, res) {
    User.find({}).then((users) =>  {
            res.status(200).send(users) 
           }).catch((err) => {return res.status(500).send("There was a problem finding the users.")
   });
});

// GETS A SINGLE USER FROM THE DATABASE
router.get('/:id',  VerifyToken, function (req, res) {
    User.findById(req.params.id, function (err, user) {
        if (err) return res.status(500).send("There was a problem finding the user.");
        if (!user) return res.status(404).send("No user found.");
        res.status(200).send(user);
    });
});

// DELETES A USER FROM THE DATABASE
router.delete('/:id',  VerifyToken,function (req, res) {
    User.findByIdAndRemove(req.params.id, function (err, user) {
        if (err) return res.status(500).send("There was a problem deleting the user.");
        res.status(200).send("User: "+ user.name +" was deleted.");
    });
});

// UPDATES A SINGLE USER IN THE DATABASE
// Added VerifyToken middleware to make sure only an authenticated user can put to this route
router.put('/:id',  VerifyToken,  function (req, res) {
    User.findByIdAndUpdate(req.params.id, req.body, {new: true}, function (err, user) {
        if (err) return res.status(500).send("There was a problem updating the user.");
        res.status(200).send(user);
    });
});


module.exports = router;
