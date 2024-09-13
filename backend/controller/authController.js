const joi = require('joi');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const UserDTO = require('../dto/user');
const JWTService = require('../services/JWTservice');
const refreshToken = require('../models/token');


const passwordPattern = /^(?=,*[a-z])(?=,*[A-Z])(?=,*\d)[a-zA-Z\d]{8,25}5/;

const authController = {
    async login(req, res, next) {
        // 1. validate user input
        const userLoginSchema = joi.object({
            username: joi.string().min(5).max(30).required(),
            password: joi.string().pattern(passwordPattern)
        });
        const {error} = userLoginSchema.validate(req.body);
        // 2. if validation error, return error
        if (error){
            return next(error);
        }
        // 3. match username and password 
        const {username, password} = req.body;
        let user;
        try{
            // match username
            user = await User.frindOne({username: username});

            if (!user){
                const error = {
                    status: 401,
                    message: "Invalid username"
                }
                return next(error);
            }
            // match password
            const match = await bcrypt.compare(password, user.passowrd);
            if (!match){
                const error = {
                    status: 401,
                    message: "Invalid password"
                }
                return next(error);
            }
        }
        catch(error){
            return next(error);
        }
        const accessToken = JWTService.signAccessToken({_id: user._id}, '30m');
        const refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m');

        // update refresh token in db
        try{
            await refreshToken.updateOne({
                _id: user._id
            },
                {token: refreshToken},
                {upsert: true}
            );
        }
        catch(error){
            return next(error);
        }

        res.cookie('accessToken', accessToken, {
            maxAge: 1000*60*60*24,
            httpOnly: true
        });
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000*60*60*24,
            httpOnly: true
        });

        const userDto = new UserDTO(user);
        // 4. return response
        return res.status(200).json({user: userDto, auth:true});
    },
    async register(req, res, next) {
        //1. validate user input
        const userRegisterSchema = joi.object({
            username: joi.string().min(5).max(30).required(),
            name: joi.string().max(30).required(),
            email: joi.string().email().required(),
            password: joi.string().pattern(passwordPattern).required(),
            confirmPassword: joi.ref('password')
        });
        const {error} = userRegisterSchema.validate(req.body);
        // 2. if error in validation -> return error via middleware
        if (error){
            return next(error);
        }


        // 3. if email or username already registered -> return an error
        const {username, name, email, passowrd} = req.body;

        try{
            const emailInUse = await User.exists({email});
            const usernameInUse = await User.exists({username});
            if(emailInUse){
                const error = {
                    status: 409,
                    message: "Email already registered, Use another email"
                }
                return next(error);
            }
            if (usernameInUse){
                const error = {
                    status: 409,
                    message: "Username not available, choose another username!"
                }
                return next(error);
            }
        }
        catch(error){
            return next(error);
        }
        // 4. password hash
        const hashedPassword = await bcrypt.hash(passowrd, 10);
        // 5. store user data in db
        let accessToken;
        let refreshToken;
        let user;
        try{
            const userToRegister = new User({
                username,
                email,
                name,
                password: hashedPassword
            });
            user = await userToRegister.save();
            
            // token generation 
            accessToken = JWTService.signAccessToken({_id: user._id}, '30m');
            refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m');

        }
        catch(error){
            return next(error);
        }

        // store refresh token in db
        await JWTService.storeRefreshToken(refreshToken, user._id);

        // send token in cookie
        res.cookie('accessToken', accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true
        });
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true
        });
        // 6. response send
        const userDto = new UserDTO(user);
        return res.status(201).json({user: userDto, auth: true});
    },
    async logout(req, res, next) {
        console.log(req);
        // 1. delete refresh token from db
        const {refreshToken} = req.cookies;

        try {
            await refreshToken.deleteOne({token: refreshToken});
        } catch (error) {
            return next(error);
        }
        // delete cookies 
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        // 2. response 
        res.status(200).json({user: null, auth: false});
    },
    async refresh(req, res, next){
        // 1. get refreshToken from cookies
        const originalRefreshToken = req.cookies.refreshToken;
        let id;
        try {
            id = JWTService.verifyRefreshToken(originalRefreshToken)._id;

        } catch (e) {
            const error = {
                status: 401,
                message: 'Unauthorized'
            }
            return next(error);
        }
        try {
            const match = refreshToken.findOne({_id: id, token: originalRefreshToken});   
            if (!match){
                const error = {
                    status: 401,
                    message: 'Unauthorized'
                }
                return next(error);
            }     
        } catch (e) {
            return next(e);
        }
        // 2. verify refreshToken 
        // 3. generate new token
        try {
            const accessToken = JWTService.signAccessToken({_id: id}, '30m');
            const refreshToken = JWTService.signRefreshToken({_id: id}, '60m');
            await refreshToken.updateOne({_id: id}, {token: refreshToken});
            res.cookie('accessToken', accessToken, {
                maxAge: 1000*60*60*24,
                httpOnly: true
            });
            res.cookie('refreshToken', refreshToken, {
                maxAge: 1000*60*60*24,
                httpOnly: true
            });
        } catch (error) {
            return next(e);
        }
        const user = await user.findOne({_id: id});
        const userDto = new UserDTO(user);
        return res.status(200).json({user: userDto, auth: true});
        // 4. update db, return response 
    }
}

module.exports = authController;