const express = require("express");
const fs = require("fs");
const methodOverride = require('method-override');
const session = require("express-session");
const path = require("path");
const bcrypt = require('bcryptjs'); // Use bcryptjs
const app = express();

app.use(methodOverride('_method'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(session({
    secret: 'mySuperSecretKey',
    resave: false,
    saveUninitialized: true
}));

const users = require("./routes/users");
app.use("/user", users);

app.get("/", (req, res) => {
    let users = JSON.parse(fs.readFileSync(path.join(__dirname, "data/users.json")));
    res.render("home.ejs", { count: users.length });
});

// Login Route
app.get('/login', (req, res) => {
    res.render("login.ejs");
});
app.post("/login", async(req, res) => {
    let { username, password } = req.body;
    let users = JSON.parse(fs.readFileSync(path.join(__dirname, "data/users.json")));
    let user = users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = user;
        res.render("login.ejs", { user });
    } else {
        res.send("Login Failed");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login");
});

app.listen(8080, () => {
    console.log("Server is running on port http://localhost:8080");
});