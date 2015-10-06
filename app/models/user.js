var mongoose = require('mongoose'),
	bcrypt = require('bcrypt-nodejs');

var UserSchema = mongoose.Schema({
	local: {
		email: String,
		password: String
	},
	facebook: {
		id: String,
		token: String,
		email: String,
		name: String
	},
	twitter: {
		id: String,
		token: String,
		displayName: String,
		username: String
	},
	google: {
		id: String,
		token: String,
		name: String,
		email: String
	}b
});

UserSchema.methods.generateHash = function( password ) {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
}

UserSchema.methods.validatePassword = function( password ) {
	return bcrypt.compareSync(password, this.local.password);
}

module.exports = mongoose.model('User', UserSchema);