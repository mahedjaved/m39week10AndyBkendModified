const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models/Users");

exports.hashPassword = async (req, res, next) => {
	if ("password" in req.body) {
		// I just had added my own salt number in process.env, I am not sure what's the point in putting in .env, just simple for me --> NOT INDUSTRY STD tho
		req.body.password = await bcrypt.hash(
			req.body.password,
			process.env.SALT
		);
	}
	next();
};

exports.auth = async (req, res, next) => {
	try {
		// no need of this since it I have removed bearer from my InstaFrontEnd
		// const token = req.header("Authorization").replace("Bearer ", "");
		const token = req.header("Authorization");
		// console.log(token);
		const decoded = jwt.verify(token, process.env.SECRET);
		const user = await User.findOne({
			_id: decoded._id,
			"tokens.token": token,
		});

		if (!user) {
			throw new Error();
		}
		req.user = user;
		req.token = token;
		next();
	} catch (error) {
		res.status(401).send({ message: "Please log in" });
	}
};
