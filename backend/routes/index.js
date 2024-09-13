const express = require('express');
const authController = require('../controller/authController');
const blogController = require('../controller/blogController');
const commentController = require('../controller/commentController');
const auth = require('../middlewares/auth');

const router = express.Router();


//testing
router.get('/test', (req, res) => res.json({msg: 'working!'}))

// user routes
// login
router.post('/login', authController.login);

// register
router.post('/register', authController.register);

// logout
router.post('/logout', auth, authController.logout);

// refresh
router.get('/refresh', authController.refresh);

// BLOGS
// create
router.post('/blog', auth, blogController.create);
// get all
router.get('/blog/all', auth, blogController.getAll);
// get blog by id 
router.get('/blog/:id', auth, blogController.getById);
// update
router.put('/blog', auth, blogController.update);
// delete
router.delete('/blog/:id', auth, blogController.delete);


// COMMENTS
// Create 
router.post('/comment', auth, commentController.create);
// get
router.get('/comments/:id', auth, commentController.getById);



module.exports =router;

