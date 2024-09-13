const joi = require('joi');
const Comment = require('../models/comment');
const CommentDTO = require('../dto/comment');

const mongodbIdPattern = /^[0-9a-fA-F]{24}$/;

const commentController = {
    async create(req, res, next){
        const createCommentSchema = joi.object({
            content: joi.string().required(),
            author: joi.string().regex(mongodbIdPattern).required(),
            blog: joi.string().regex(mongodbIdPattern).required()
        });

        const {error} = createCommentSchema.validate(req.body);
        if (error){
            return next(error);
        }
        const {content, author, blog} = req.body;

        try {
            const newComment = new Comment({
                content, author, blog
            });
            await newComment.save();
        } catch (error) {
            return next(error);
        }
        return res.status(201).json({message: 'Comment Created'});
    },
    async getById(req, res, next){
        const getByIdSchema = joi.object({
            id: joi.string().regex(mongodbIdPattern).required()
        });

        const {error} = getByIdSchema.validate(req.params);
        if (error){
            return next(error);
        }

        const {id} = req. params;

        let comments;

        try {
            comments = await Comment.find({blog: id}).populate('author');
        } catch (error) {
            return next(error);
        }

        let commentsDto = [];
        for(let i = 0; i < comments.length; i++){
            const obj = new CommentDTO(comments[i]);
            commentsDto.push(obj);
        }

        return res.status(200).json({data: commentsDto});
    }
}

module.exports = commentController;