const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const users = require("./routes/users");
app.use("/user", users);

app.get("/", (req, res) => {
    let users = JSON.parse(fs.readFileSync(path.join(__dirname, "data/users.json")));
    res.render("home.ejs", { count: users.length });
});

app.listen(8080, () => {
    console.log("Server is running on port http://localhost:8080");
});