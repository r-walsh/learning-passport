var LocalStrategy = require('passport-local').Strategy,
	FacebookStrategy = require('passport-facebook').Strategy,
	TwitterStrategy = require('passport-twitter').Strategy,
	GoogleStrategy = require('passport-google-oauth2').Strategy,
	configAuth = require('./auth'),
	User = require('../app/models/user.js');

module.exports = function( passport ) {

	passport.serializeUser(function( user, done ) {
		done(null, user.id);
	});

	passport.deserializeUser(function( id, done ) {
		User.findById(id, function(err, user) {
			done(err, user);
		});
	});

	//////////
	//LOCAL///
	//////////

	passport.use('local-signup', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
		}, function( req, email, password, done) {
			process.nextTick(function() {

				User.findOne({ 'local.email': email }, function( err, user ) {
					if (err) {
						return done(err);
					}
					if (user) {
						return done(null, false,  req.flash('signupMessage', 'That email is already in use'));
					} else {
						var newUser = new User();

						newUser.local.email = email;
						newUser.local.password = newUser.generateHash(password);

						newUser.save(function(err) {
							if (err) {
								throw err;
							}
							return done(null, newUser);
						});
					}
				});
			});
		}
	));

	passport.use('local-login', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	}, function( req, email, password, done ) {

		User.findOne({ 'local.email': email }, function( err, user ) {
			if (err) {
				return done(err);
			}

			if (!user) {
				return done(null, false, req.flash('loginMessage', 'No user found'));
			}

			if (!user.validatePassword( password )) {
				return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
			}

			return done(null, user);
		});

	}));

	////////////
	//FACEBOOK//
	////////////

	passport.use(new FacebookStrategy({

		clientID: configAuth.facebookAuth.clientID,
		clientSecret: configAuth.facebookAuth.clientSecret,
		callbackURL: configAuth.facebookAuth.callbackURL

	}, function( token, refreshToken, profile, done ) {

		process.nextTick(function() {
			User.findOne({ 'facebook.id': profile.id }, function(err, user) {
				if (err) {
					return done(err);
				}

				if (user) {
					return done(null, user);
				} else {
					console.log(profile);
					var newUser = new User();

					newUser.facebook.id = profile.id;
					newUser.facebook.token = token;

					if (profile.name.givenName && profile.name.familyName) {
						newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
					} else {
						newUser.facebook.name = profile.displayName;
					}

					if (profile.emails) {
						newUser.facebook.email = profile.emails[0].value;
					}

					newUser.save(function (err) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					});
				}
			});
		});
	}));

	///////////
	//TWITTER//
	///////////

	passport.use(new TwitterStrategy({

		consumerKey: configAuth.twitterAuth.consumerKey,
		consumerSecret: configAuth.twitterAuth.consumerSecret,
		callbackURL: configAuth.twitterAuth.callbackURL

	}, function( token, tokenSecret, profile, done) {
		process.nextTick(function() {

			User.findOne({ 'twitter.id': profile.id }, function(err, user) {
				if (err) {
					return done(err);
				}

				if (user) {
					return done(null, user);
				} else {
					var newUser = new User();

					newUser.twitter.id = profile.id;
					newUser.twitter.token = token;
					newUser.twitter.username = profile.username;
					newUser.twitter.displayName = profile.displayName;

					newUser.save(function(err) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					});
				}
			});
		});
	}));

	//////////
	//GOOGLE//
	//////////

	passport.use(new GoogleStrategy({

		clientID: configAuth.googleAuth.clientID,
		clientSecret: configAuth.googleAuth.clientSecret,
		callbackURL: configAuth.googleAuth.callbackURL

	}, function( token, refreshToken, profile, done ) {
		process.nextTick(function() {

			User.findOne({ 'google.id': profile.id }, function( err, user ) {
				if (err) {
					return done(err);
				}

				if (user) {
					return done(null, user);
				} else {
					var newUser = new User();

					newUser.google.id = profile.id;
					newUser.google.token = token;
					newUser.google.name = profile.displayName;
					newUser.google.email = profile.emails[0].value;

					newUser.save(function ( err ) {
						if (err) {
							throw err;
						}

						return done(null, newUser);
					})
				}
			})
		})
	}))



}