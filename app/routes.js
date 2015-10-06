module.exports = function( app, passport ) {
	
	app.get('/', function(req, res) {
		res.render('index.ejs');
	});

	app.get('/profile', isLoggedIn, function(req, res) {
		res.render('profile.ejs', {
			user: req.user
		});
	});

	app.get('/logout', function(req, res) {
		ereq.logout();
		res.redirect('/');
	});

	////////////////
	//LOCAL ROUTES//
	////////////////

	app.get('/login', function(req, res) {
		res.render('login.ejs', { message: req.flash('loginMessage') });
	});

	app.post('/login', passport.authenticate('local-login', {
		successRedirect: '/profile',
		failureRedirect: '/login',
		failureFlash: true
	}));

	app.get('/signup', function(req, res) {
		res.render('signup.ejs', { message: req.flash('signupMessage') });
	});

	app.post('/signup', passport.authenticate('local-signup', {
		successRedirect: '/profile',
		failureRedirect: '/signup',
		failureFlash: true
	}));

	///////////////////
	//FACEBOOK ROUTES//
	///////////////////

	app.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));

	app.get('/auth/facebook/callback', passport.authenticate('facebook', {
		successRedirect: '/profile',
		failureRedirect: '/'
	}));

	//////////////////
	//TWITTER ROUTES//
	//////////////////

	app.get('/auth/twitter', passport.authenticate('twitter'));

	app.get('/auth/twitter/callback', 
		passport.authenticate('twitter', {
			successRedirect: '/profile',
			failureRedirect: '/'
		}));

	/////////////////
	//GOOGLE ROUTES//
	/////////////////

	app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

	app.get('/auth/google/callback', 
		passport.authenticate('google', {
			successRedirect: '/profile',
			failureRedirect: '/'
		}));
};

function isLoggedIn( req, res, next ) {
	if (req.isAuthenticated()) {
		return next();
	}

	res.redirect('/');
}