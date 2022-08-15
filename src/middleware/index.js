const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models/Users");

exports.hashPassword = async (req, res, next) => {
	try {
		if ("password" in req.body) {
			// I just had added my own salt number in process.env, --> NOT RECOMMENDED tho, AND PROVEN TO NOT WORK
			req.body.password = await bcrypt.hash(req.body.password, 8);
		}
		// res.send({ hashMsg: "Passed the hash successfully" });
		next();
	} catch (error) {
		res.status(401).send({ message: "Hash failed" });
	}
};

exports.auth = async (req, res, next) => {
	try {
		// no need of this since it I have removed bearer from my InstaFrontEnd
		// const token = req.header("Authorization").replace("Bearer ", "");
		// check if token is in the header or in the body
		const token =
			typeof req.header("Authorization") === "string"
				? req.header("Authorization")
				: req.body.token;
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
		res.status(401).send({ message: "Failed authorization" });
	}
};
