require("dotenv").config()
//this will allow us to pull params from .env file
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const users = []
const jwt = require("jsonwebtoken")

app.use(express.json())
//This middleware will allow us to pull req.body.<params>
const port = process.env.TOKEN_SERVER_PORT
//get the port number from .env file
app.listen(port, () => {
    console.log(`Authorization Server running on ${port}...`)
})
app.post("/createUser", async (req, res) => {
    const user = req.body.name
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    users.push({ user: user, password: hashedPassword })
    res.status(201).send(users)
    console.log(users)
})

//AUTHENTICATE LOGIN AND RETURN JWT TOKEN
app.post("/login", async (req, res) => {
    const user = users.find((c) => c.user == req.body.name)
    //check to see if the user exists in the list of registered users
    if (user == null) res.status(404).send("User does not exist!")
    //if user does not exist, send a 400 response
    if (await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken({ user: req.body.name })
        const refreshToken = generateRefreshToken({ user: req.body.name })
        res.json({ accessToken: accessToken, refreshToken: refreshToken })
    }
    else {
        res.status(401).send("Password Incorrect!")
    }
})