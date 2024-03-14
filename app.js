require('dotenv').config();
require('./config/database');
require('./config/passport');
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const User = require('./models/user.model');

const app = express();

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Using passport for token validation
app.use(passport.initialize());

// home route
app.get('/', (req, res) => {
  res.send('<h1>Welcome to the home route</h1>');
});

// register route
app.post('/register', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // hash the password and save the user
    bcrypt.hash(req.body.password, saltRounds, async function (err, hash) {
      const newUser = new User({
        username: req.body.username,
        password: hash,
      });

      await newUser
        .save()
        .then((user) => {
          res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: {
              id: user._id,
              username: user.username,
            },
          });
        })
        .catch((error) => {
          res
            .status(500)
            .json({ success: false, message: 'Error saving user', error });
        });
    });
  } catch (error) {
    res.status(500).json({ message: 'Register route error' });
  }
});

// login route
app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: 'User does not exist' });
    }

    // compare the password from db with the request password
    if (!bcrypt.compareSync(req.body.password, user.password)) {
      return res
        .status(400)
        .json({ success: false, message: 'Invalid password' });
    }

    const payload = {
      id: user._id,
      username: user.username,
    };

    const access_token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
      expiresIn: '1m',
    });

    const refresh_token = jwt.sign(
      payload,
      process.env.JWT_REFRESH_SECRET_KEY,
      {
        expiresIn: '1d',
      }
    );

    res.cookie('refreshToken', refresh_token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    return res.status(200).json({
      success: true,
      message: 'User logged in successfully',
      user: {
        id: user._id,
        username: user.username,
      },
      access_token: 'Bearer ' + access_token,
      refresh_token: 'Bearer ' + refresh_token,
    });
  } catch (error) {
    res.status(500).json({ message: 'Login route error' });
  }
});

// Protected profile route with token validation
app.get(
  '/profile',
  passport.authenticate('jwt', { session: false }),
  function (req, res) {
    return res.status(200).json({ success: true, user: req.user });
  }
);

// Refresh token route
app.post('/refresh-token', (req, res) => {
  try {
    const refreshToken = req.headers['x-refresh-token'].split(' ')[1]; // Bearer <token>, so we split it to get the token

    console.log({ refreshToken: req.headers['x-refresh-token'] });

    if (!refreshToken) {
      return res.status(401).json({ message: 'User not authenticated' });
    }
    console.log('before verify');
    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET_KEY,
      (err, user) => {
        console.log({ err, user });
        if (err) {
          return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const payload = {
          id: user.id,
          username: user.username,
        };

        const access_token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
          expiresIn: '1m',
        });

        const refresh_token = jwt.sign(
          payload,
          process.env.JWT_REFRESH_SECRET_KEY,
          {
            expiresIn: '1d',
          }
        );

        res.cookie('refreshToken', refresh_token, {
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
        });

        return res.status(200).json({
          success: true,
          message: 'Token refreshed successfully',
          access_token: 'Bearer ' + access_token,
          refresh_token: 'Bearer ' + refresh_token,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Refresh token route error' });
  }
});

// resource not found
app.use((req, res, next) => {
  res.status(404).json({ message: 'Resource not found' });
});

// server error
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Server error' });
});

module.exports = app;
