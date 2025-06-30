require('dotenv').config();
const jwt = require('jsonwebtoken');

exports.generateToken = (payload, passwordReset = false) => {
  const secret = process.env.SECRET_KEY;

  if (!secret) {
    throw new Error("JWT secret key (SECRET_KEY) is not defined in .env");
  }

  const expiresIn = passwordReset
    ? process.env.PASSWORD_RESET_TOKEN_EXPIRATION || '15m'
    : process.env.LOGIN_TOKEN_EXPIRATION || '7d';

  return jwt.sign(payload, secret, { expiresIn });
};
