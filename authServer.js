require("dotenv").config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const users = []
const jwt = require("jsonwebtoken")
const port = process.env.TOKEN_SERVER_PORT
let refreshTokens = []
function generateAccessToken(user) {
    return
    jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" })
}

function generateRefreshToken(user) {
    const refreshToken =
        jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "20m" })
    refreshTokens.push(refreshToken)
    return refreshToken
}

app.use(express.json())

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


app.post("/login", async (req, res) => {
    const user = users.find((c) => c.user == req.body.name)
    if (user == null) res.status(404).send("User does not exist!")
    if (await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken({ user: req.body.name })
        const refreshToken = generateRefreshToken({ user: req.body.name })
        res.json({ accessToken: accessToken, refreshToken: refreshToken })
    }
    else {
        res.status(401).send("Password Incorrect!")
    }
})

app.post("/refreshToken", (req, res) => {
    if (!refreshTokens.includes(req.body.token)) res.status(400).send("Refresh Token Invalid")
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    const accessToken = generateAccessToken({ user: req.body.name })
    const refreshToken = generateRefreshToken({ user: req.body.name })
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

app.delete("/logout", (req, res) => {
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    res.status(204).send("Logged out!")
})

