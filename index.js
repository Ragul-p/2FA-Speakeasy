// TOPT  -> Time Based One Time Password
// npm i express uuid speakeasy  node-json-db
// npm i -D nodemon


const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const QRCode = require("qrcode");

const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");

const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());

const db = new JsonDB(new Config("myDatabase", true, false, '/'));


app.get("/api/register", (req, res) => {
    try {
        const id = uuid.v4();
        const path = `/user/${id}`

        const temp_secret = speakeasy.generateSecret();

        db.push(path, { id, temp_secret })

        QRCode.toDataURL(temp_secret.otpauth_url, (error, data) => {
            res.write("<h1>scan authenticator app to get topt</h1>");
            res.write("<h3>user id :    " + id + "</h3>");
            res.write('<h4>base32 : ' + temp_secret.base32 + '</h4>');
            res.write('<img src="' + data + '"/>');
            res.send();
        })

        // res.json({ id, secret: temp_secret });

    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "generating the secret" })
    }
});



app.post("/api/verify", async (req, res) => {
    try {
        const { otp, userId } = req.body;

        const path = `/user/${userId}`;
        const user = await db.getData(path);

        const { "base32": secret } = user.temp_secret;

        const token = speakeasy.totp({
            secret,
            encoding: "base32"
        })
        console.log(token);

        const verified = speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token: otp
        })


        if (verified) {
            db.push(path, { id: userId, secret: user.temp_secret })
            res.json({ verified: true })
        } else {
            res.json({ verified: false })
        }

    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "generating the secret" })
    }
});




app.post("/api/validate", async (req, res) => {
    try {
        const { otp, userId } = req.body;

        const path = `/user/${userId}`;
        const user = await db.getData(path);
        const { "base32": secret } = user.secret;

        const tokenValidates = speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token: otp,
            window: 2
        })


        if (tokenValidates) {
            res.json({ validated: true })
        } else {
            res.json({ validated: false })
        }

    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "generating the secret" })
    }
});


app.listen(PORT, () => {
    console.log(`Sever is listening on port ${PORT}`);
});