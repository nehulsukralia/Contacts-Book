const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

//@desc Register a user
//@route POST /api/users/register
//@access public
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    res.status(400);
    throw new Error("All fields are mandatory");
  }

  // check if user already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log("Hashed Pasword: ", hashedPassword);

  // create user
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });

  console.log(`User create ${user}`);
  if (user) {
    res.status(201).json({ _id: user.id, email: user.email });
  } else {
    res.status(400);
    throw new Error("User data is not valid");
  }
});

//@desc Login a user
//@route POST /api/users/register
//@access public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400);
    throw new Error("All fields are mandatory");
  }

  // now find the user
  const user = await User.findOne({ email });

  // compare password with hashedpassword
  if (user && (await bcrypt.compare(password, user.password))) {
    // create a token
    const accessToken = jwt.sign({
      user: {
        username: user.username,
        email: user.email,
        id: user.id,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m"}
    );

    res.status(200).json({ accessToken})
  } else {
    res.status(401);
    throw new Error("Invalid credentials")
  }
});

//@desc Current user info
//@route POST /api/users/register
//@access private
const currentUser = asyncHandler(async (req, res) => {
  res.json(req.user); // req.user is coming from the validateToken middleware
});

module.exports = { registerUser, loginUser, currentUser };
