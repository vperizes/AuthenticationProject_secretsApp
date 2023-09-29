import express from "express";
import ejs from "ejs";
import bodyParser from "body-parser";
import mongoose, { Schema } from "mongoose";
import 'dotenv/config';
import bcrypt from "bcrypt";
//import encrypt from "mongoose-encryption";
//import md5 from "md5";

////Database set up
const DATABASE_URI = "mongodb://127.0.0.1:27017/userDB";


//setting up connection to mongo server and creating (or accessing if already created) todoDB
mongoose.connect(DATABASE_URI);


//schema for users
const userSchema = new Schema({
    email: {
        type: String,
        requried: true
    },
    password: {
        type: String,
        required: true
    }
});

//establishing encrytpion, specifically encrypting user passwords
const saltRounds = 10;
//const secret = process.env.SECRET;
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });

//collection for all users
const User = mongoose.model("User", userSchema);


const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = 3000;

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/register", (req, res) => {

    async function saltHashPassword() {
        try {
            const username = req.body.username;
            const password = req.body.password;

            const salted_hashPass = await bcrypt.hash(password, saltRounds);

            const newUser = new User({
                email: username,
                password: salted_hashPass
            });

            newUser.save();
            res.render("secrets.ejs");

        } catch (error) {
            console.log(error);
        }
    }

    saltHashPassword();

});

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    async function findExistingUser() {
        try {
            const foundUser = await User.findOne({ email: username }).exec();

            //comparing hashed passwords
            bcrypt.compare(password, foundUser.password, (err, result) => {
                if (result === true) {
                    res.render("secrets.ejs");
                } else {
                    console.log(err);
                    res.status(401).json({ err: "password does not match username." });
                }
            });



        } catch (error) {
            res.status(404).json({ error: `User: '${username}' not found. This user does not exist` });
            console.log(error);
        }
    }

    findExistingUser();
});


app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}.`);
});



