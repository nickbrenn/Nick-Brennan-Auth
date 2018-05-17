const express = require("express");
const helmet = require("helmet");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");

const User = require("./users/User");
const secret = "SECRET?";

mongoose
  .connect("mongodb://localhost/authdb")
  .then(conn => console.log("\n... API Connected to Database ...\n"))
  .catch(err => console.log("\n*** ERROR Connecting to Database ***\n", err));

const server = express();

const localStrategy = new LocalStrategy(function(username, password, done) {
  User.findOne({ username })
    .then(user => {
      if (!user) {
        done(null, false);
      } else {
        user
          .comparePassword(password)
          .then(isValid => {
            if (isValid) {
              const { _id, username } = user;
              return done(null, { _id, username });
            } else {
              return done(null, false);
            }
          })
          .catch(err => {
            return done(err);
          });
      }
    })
    .catch(err => done(err));
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secret
};

const jwtStrategy = new JwtStrategy(jwtOptions, function(payload, done) {
  User.findById(payload.sub)
    .then(user => {
      if (user) {
        done(null, user);
      } else {
        done(null, false);
      }
    })
    .catch(err => {
      done(err);
    });
});

passport.use(localStrategy);
passport.use(jwtStrategy);

const passportOptions = { session: false };
const authenticate = passport.authenticate("local", passportOptions);
const protected = passport.authenticate("jwt", passportOptions);

function makeToken(user) {
  const timestamp = new Date().getTime();
  const payload = {
    sub: user._id,
    iat: timestamp,
    username: user.username,
    role: user.role
  };
  const options = {
    expiresIn: "24h"
  };

  return jwt.sign(payload, secret, options);
}

server.use(helmet());
server.use(express.json());

server.get("/", (req, res) => {
  res.send({ route: "/", message: req.message });
});

server.post("/register", function(req, res) {
  const user = new User(req.body);
  user
    .save()
    .then(user => {
      const token = makeToken(user);
      res.status(201).json({ user, token });
    })
    .catch(err => res.status(500).json(err));
});

server.post("/login", authenticate, (req, res) => {
  res.status(200).json({ token: makeToken(req.user), user: req.user });
});

server.get("/users", protected, (req, res) => {
  User.find()
    .select("username")
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

const port = process.env.PORT || 5000;
server.listen(port, () => {
  console.log(`Server up and running on ${port}`);
});
