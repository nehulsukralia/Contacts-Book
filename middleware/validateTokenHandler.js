const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const validateToken = asyncHandler(async (req, res, next) => {
    let token;
    let authHeader = req.headers.Authorization || req.headers.authorization; // checked with both spelling because different request makers can use different spellings

    if (authHeader && authHeader.startsWith("Bearer")) {
        token = authHeader.split(" ")[1]; // extrated the token
        //verify the token
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if(err) {
                res.status(401);
                throw new Error("User is not authorized");
            }

            req.user = decoded.user; // decoded is the jwt payload and we took the user object from the payload and req.user is a custom key we make in the req object to hold any data
            next();
        })

        if(!token) {
            res.status(401);
            throw new Error("User is not authorized or token is missing")
        }
    }
})

module.exports = validateToken;