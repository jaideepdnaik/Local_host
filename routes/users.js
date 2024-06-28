const express = require("express");
const path = require("path");
const fs = require("fs");
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const router = express.Router();
const saltRounds = 10;

// Function to get the list of users from users.json
const getUsers = () => {
    try {
        const data = fs.readFileSync(path.join(__dirname, "../data/users.json"));
        return JSON.parse(data);
    } catch (error) {
        console.log("Error while reading users.json: ", error);
        return [];
    }
};

// Function to save new users to users.json
const saveUsers = (users) => {
    try {
        const data = JSON.stringify(users, null, 2);
        if (!data) {
            throw new Error('Failed to convert users to JSON string');
        }
        fs.writeFileSync(path.join(__dirname, '../data/users.json'), data, 'utf8');
    } catch (error) {
        console.error('Error saving users:', error.message);
        throw error;
    }
};

const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        next();
    } else {
        res.status(403).send("Access Denied");
    }
};

// View the users (only accessible by admin)
router.get("/", isAdmin, (req, res) => {
    let users = getUsers();
    res.render("users.ejs", { data: users });
});

// Add new user
router.get("/new", (req, res) => {
    res.render("new.ejs");
});

router.post("/new", async (req, res) => {
    let { username, email, password } = req.body;
    let users = getUsers();
    let id = uuidv4();
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        users.push({ id, username, email, password: hashedPassword });
        saveUsers(users);
        res.redirect("/");
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).send("Error creating user");
    }
});

// Edit route
router.get("/:id/edit", (req, res) => {
    let { id } = req.params;
    let users = getUsers();
    let user = users.find(u => u.id === id);
    res.render("edit.ejs", { user });
});

router.patch("/:id", async (req, res) => {
    let { id } = req.params;
    let { username, password } = req.body;
    let users = getUsers();
    let user = users.find(u => u.id === id);
    
    try {
        if(await bcrypt.compare(password, user.password)) {
            user.username = username;
            saveUsers(users);
            res.redirect("/user");
        } else {
            res.send("Wrong password");
        }
    } catch(error) {
        console.log("Error comparing passwords ", error);
        res.send("Error updating user");
    }
});

// Delete Route
router.get("/:id/delete", (req, res) => {
    let { id } = req.params;
    let users = getUsers();
    let user = users.find(u => u.id === id);
    res.render("delete.ejs", { user });
});

router.delete("/:id", async(req, res) => {
    let { id } = req.params;
    let { password } = req.body;
    let users = getUsers();
    let user = users.find(u => u.id === id);
    try {
        if (await bcrypt.compare(password, user.password)) {
            users = users.filter(u => u.id !== id);
            saveUsers(users);
            res.redirect("/user");
        } else {
            res.send("Wrong password!");
        }
    } catch (error) {
        console.error("Error comparing passwords:", error);
        res.status(500).send("Error deleting user");
    }
});

module.exports = router;
