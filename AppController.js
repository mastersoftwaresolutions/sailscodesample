/**
 * AppController
 *
 * @description :: Server-side logic for managing apps
 * @help        :: See http://links.sailsjs.org/docs/controllers
 */
module.exports = {
    issues: function(req, res) {
        function getArticles(ids, cb) {
            Article.find({
                id: ids
            }).exec(function(err, articles) {
                cb(articles);
            });
        }

        Issue.find({}).exec(function(err, issues) {
            i = 0;
            var recursiveCall = function(articles) {
                if (i > 0) issues[i - 1].articles = articles;
                if (i == issues.length) {
                    return res.json(issues);
                }
                getArticles(issues[i].articles, recursiveCall);
                i++;
            };

            recursiveCall();

        });
    },

    issue: function(req, res) {
        Issue.findOne(req.param('id')).then(function(issue) {
            var articles = Article.find().where({
                id: issue.articles
            }).then(function(list) {

                _.each(list, function(article) {
                    article.pages = Page.find().where({
                        id: article.pages
                    }).then(function(pages) {
                        return pages;
                    })
                });

                return list;
            });

            return articles;

        }).spread(function(articles) {
            res.json(articles);
        }).fail(function(err) {
            res.json(err, 500);
        });
    },

    article: function(req, res) {
        var id = req.params('id');
        Article.findOne(id).exec(function(err, article) {
            if (err) res.send(err, 500);
            if (!article) res.send('Can not find article', 404);

            res.json(article);
        });
    },

    register: function(req, res) {
        if (!req.body) {
            return res.json({error:sails.config.validationMessage.userMissing});
        }
        var user = _.pick(req.body, 'username', 'email', 'password', 'role');
        if (!user.username) {
            return res.json({error:sails.config.validationMessage.userMissing});
        }
        if (!user.email) {
            return res.json({error:sails.config.validationMessage.emailMissing});
        }
        if (!user.password) {
            return res.json({error:sails.config.validationMessage.passwordMissing});
        }
        if (!user.role) {
            return res.json({error:sails.config.validationMessage.roleMissing});
        }
        AppUser.findOne({
            "username": user.username
        }).exec(function(err, userFind) {
            if (err) return res.json(error, 500);
            if (userFind) 
            return res.json({error:sails.config.validationMessage.userExists});
            AppUser.findOne({
                "email": user.email
            }).exec(function(err, emailFind) {
                if (err) return res.json(error, 500);
                if (emailFind) 
                    return res.json({error:sails.config.validationMessage.emailExists});
                AppUser.create(user).exec(function(error, createUser) {
                    if (error) return res.json(error, 400);
                    var pass = {};
                    pass.protocol = 'local';
                    pass.user = createUser;
                    pass.password = user.password;
                    AppPassport.validate(pass, function(errPass, validPass) {
                        if (errPass) return res.json(error, 400);
                        AppPassport.create({
                            protocol: 'local',
                            password: user.password,
                            user: createUser.id
                        }, function(err, passport) {
                            if (err) {
                                if (err.code === 'E_VALIDATION') {
                                    AppUser.destroy(createUser.id).exec(function() {});
                                    return res.json(error, 400);
                                }
                            }
                            return res.json(createUser);
                        });
                    });
                });
            });
        });
    },

    signin: function(req, res) {
        var bcrypt = require('bcrypt');
        var validator = require('validator');
        if (!req.body) {
            return res.json({error:sails.config.validationMessage.userMissing});
        }
        if (!req.body.identifier) {
            return res.json({error:sails.config.validationMessage.userMissing});
        }
        if (!req.body.password) {
            return res.json({error:sails.config.validationMessage.passwordMissing});
        }
        var isEmail = validator.isEmail(req.body.identifier),
            query = {};
        if (isEmail) {
            query.email = req.body.identifier;
        } else {
            query.username = req.body.identifier;
        }     
        AppUser.findOne(query).exec(function(err, user) { 
            if (err) return res.json({error: 'DB error'}, 500);
            if (!user) return res.json({error: 'User not found'}, 404);
            AppPassport.findOne({
                user: user.id
            }).exec(function(passError, findPass) {   
                if (passError) return res.json({error: tokenError}, 500);
                findPass.validatePassword(req.body.password, function(errorPassword, match) { 
                    if (errorPassword) return res.json({error: errorPassword}, 500);
                    if (match) { // password match
                        var authenticate = sailsTokenAuth.issueToken({
                            sid: user.id
                        });

                        Token.create({ //store auth token
                            appuser: user.id,
                            token: authenticate,
                            expiredOn:new Date() //replace in Model 
                        }).exec(function(tokenError, authToken) {  
                            if (tokenError) return res.json({error: tokenError},500);
                            return res.json({user: user,token: authenticate});
                        });
                        return res.json({user: user,token: authenticate});
                    } else {
                        // invalid password
                        return res.json({error: 'Invalid password'}, 400);
                    }
                });
            });
        });        
    },

    update: function(req, res) {
        var user = _.pick(req.body, 'username', 'email', 'password', 'usertype');
        if (!req.body.password) {
            return res.json({error:sails.config.validationMessage.passwordMissing});
        }
        AppUser.findOne({
            id: req.user.id
        }).exec(function(userErr, user) {
            if (userErr) return res.json({error: userErr}, 500);
            AppPassport.update({
                user: req.user.id
            }, {
                password: req.body.password
            }).exec(function(passError, passUpdate) {
                if (passError) return res.json({error: passError}, 500);
                return res.json({"message": "Password updated successfully"});
            });
        });
    },

    // customerlogin: function(req, res){
    //     var bcrypt = require('bcrypt');
    //     var validator = require('validator');
    //     if (!req.body) {
    //         return res.json({error:sails.config.validationMessage.userMissing});
    //     }
    //     if (!req.body.identifier) {
    //         return res.json({error:sails.config.validationMessage.userMissing});
    //     }
    //     if (!req.body.password) {
    //         return res.json({error:sails.config.validationMessage.passwordMissing});
    //     }
    //     var isEmail = validator.isEmail(req.body.identifier),
    //         query = {};
    //     if (isEmail) {
    //         query.email = req.body.identifier;
    //     } else {
    //         query.username = req.body.identifier;
    //     }

    //     User.findOne(query).exec(function(err, user) { 
    //         if (err) return res.json({error: 'DB error'}, 500);
    //         if (!user) return res.json({error: 'User not found'}, 404);
    //         Passport.findOne({
    //             user: user.id
    //         }).exec(function(passError, findPass) {   
    //             if (passError) return res.json({error: tokenError}, 500);
    //             findPass.validatePassword(req.body.password, function(errorPassword, match) { 
    //                 if (errorPassword) return res.json({error: errorPassword}, 500);
    //                 if (match) { // password match
    //                     var authenticate = sailsTokenAuth.issueToken({
    //                         sid: user.id
    //                     });

    //                     Token.create({ //store auth token
    //                         appuser: user.id,
    //                         token: authenticate,
    //                         expiredOn:new Date() //replace in Model 
    //                     }).exec(function(tokenError, authToken) {  
    //                         if (tokenError) return res.json({error: tokenError},500);
    //                         return res.json({user: user,token: authenticate});
    //                     });
    //                 } else {
    //                     // invalid password
    //                     return res.json({error: 'Invalid password'}, 400);
    //                 }
    //             });
    //         });
    //     });
    // },

    logout: function(req, res) {
        Token.destroy({
            appuser: req.user.id
        }).exec(function(userErr, user) {
            if (userErr) return res.json({error: userErr}, 500);
            return res.json({"message": "Logged out successfully"});
        });       
    }
};