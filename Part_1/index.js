const express = require("express");
const session = require("express-session");
const path = require("path");
const pg = require("pg");
const bcrypt = require("bcrypt");

const pool = new pg.Pool({
  user: "me",
  host: "localhost",
  database: "sprint2",
  password: "password",
  port: 5432,
});

const app = express();
app.use(session({ secret: "UniqueSession" }));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.get("/", function (req, res) {
  if (req.session.count === undefined) {
    req.session.count = 0;
  }
  const count = req.session.count;
  req.session.count = req.session.count + 1;
  res.send(`You've visited ${count} times!`);
});

app.get("/signup", function (req, res) {
  res.sendFile(path.join(__dirname, "signup.html"));
});

app.post("/signup", async function (req, res) {
  let email = req.body.email;
  let password = req.body.password;
  let password_confirm = req.body.confirm_password;
  let role = req.body.role;
  if (!email || !password || !password_confirm) {
    res.send("Error! Please fill in all fields.");
  } else {
    if (password !== password_confirm) {
      res.send(
        "Password confirmation does not match password. Please try again."
      );
      console.log(password, password_confirm);
    } else {
      let encrypted_password = await bcrypt.hash(password, 10);
      let results = await pool.query("SELECT * FROM users WHERE email=$1", [
        email
      ]);
      if (results.rows.length > 0) {
        res.send("Error! There is already an account with that name!");
      } else {
        let insert_result = await pool.query(
          "INSERT INTO users(email, password, role) VALUES($1, $2, $3)",
          [email, encrypted_password, role]
        );
        res.send("The account has been created");
      }
    }
  }
});

app.get("/login", function (req, res) {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.post("/login", async function (req, res) {
  const email = req.body.email;
  const password = req.body.password;
  const role = req.body.role;

  let results = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (results.rows < 1) {
    res.send(
      "Account not found. Try again, or sign up if you don't yet have an account."
    );
  } else if (results.rows > 1) {
    console.warning(
      "That's weird... Multiple accounts with this email address exist. This shouldn't normally happen."
    );
    res.send(
      "That's weird... Multiple accounts with this email address exist. This shouldn't normally happen."
    );
  } else {
    const stored_password = results.rows[0].password;
    const stored_role = results.rows[0].role;
    bcrypt.compare(password, stored_password, (err, result) => {
      if (result) {
        if (role === stored_role) {
          req.session.loggedIn = true;
          res.send("You are now logged in.");
        } else {
          res.send("Your selected role does not match the role that we have on file for you.")
        }
      } else {
        res.send("Invalid password! Please try again!");
      }
    });
  }
});

app.get("/secret", function (req, res) {
  if (req.session.loggedIn == true) {
    res.send("The secret message is: there is no secret!");
  } else {
    res.send("You must be logged in to see the secret message.");
  }
});

app.get("/logout", function (req, res) {
  res.sendFile(path.join(__dirname, "logout.html"));
});

app.post("/logout", function (req, res) {
  req.session.loggedIn = false;
  res.send("You have successfully logged out.");
});

app.listen(3000, function () {
  console.log("Listening at http://localhost:3000");
});
