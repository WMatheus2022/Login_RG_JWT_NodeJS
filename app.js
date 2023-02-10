require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config Json
app.use(express.json());

// Model
const User = require("./models/User");

// Open route - public route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to our API" });
});
// private route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  // check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "user not found" });
  }
  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "access denied" });
  }
  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ msg: "token invalid" });
  }
}

// Register users
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  // Validator
  if (!name) {
    return res.status(422).json({ msg: " The name is required!!" });
  }
  // email required
  if (!email) {
    return res.status(422).json({ msg: " The email is required!!" });
  }
  // password required
  if (!password) {
    return res.status(422).json({ msg: " The password is required!!" });
  }
  // password not is correct
  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "password not correct!" });
  }

  // check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: " Please, use an email existing!" });
  }
  // create passeword
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // create user
  const user = new User({
    name,
    email,
    password,
    passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Conection create with success!!" });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: "Error trying to connect to server, please try again later!",
    });
  }
});

// check Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  // email required
  if (!email) {
    return res.status(422).json({ msg: " The email is required!!" });
  }
  // password required
  if (!password) {
    return res.status(422).json({ msg: " The password is required!!" });
  }

  // check usurs exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "User not found!" });
  }

  // check if password match
  const checkpassword = await bcrypt.compare(password, user.password);
  if (!checkpassword) {
    return res.status(422).json({ msg: "password mismatch!" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({ msg: " authentic accomplish success", token });
  } catch (err) {
    console.log(error);
    res.status(500).json({
      msg: "Error trying to connect to server, please try again later!",
    });
  }
});

// Credencias
const dbUsers = process.env.DB_USERS;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUsers}:${dbPassword}@cluster0.zmiyzo8.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Connection to database with success!!");
  })
  .catch((err) => {
    console.log(err);
  });
