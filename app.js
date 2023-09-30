import express from "express";
import bodyParser from "body-parser";
import mongoose, { Schema } from "mongoose";
import 'dotenv/config';
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";

//main config
const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const PORT = 3000;

////Database set up
const DATABASE_URI = "mongodb://127.0.0.1:27017/userDB";

//setting up connection to mongo server and creating (or accessing if already created) todoDB
mongoose.connect(DATABASE_URI);


//schema for users
const userSchema = new Schema({
    email: String,
    password: String
});

//using this plugin to hash and salt passwords and save users to mongoDB database
userSchema.plugin(passportLocalMongoose);

//collection for all users
const User = mongoose.model("User", userSchema);

//config passport and passport local
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
    //if user is already logged in then render secrets page, if not then redirect to login
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if(err){
            console.log(err);
        } else{
            res.redirect("/");
        }
    });  
});

app.post("/register", (req, res) => {

    //using passport-local-mongoose package (.register() method) to handle creating + saving new user 
    //and interacting with mongoose directly
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            //if no errors authenticate user using passport.
            //call back is only triggered if authentication was successful (i.e. set up cookie that saved current logged in session)
            passport.authenticate("local", { failureRedirect: "/register" })(req, res, () => {
                //user gets redirected if already logged in through cookie auth
                res.redirect("/secrets");
            });
        }
    })

});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    //using passport to login user and authenticate them
    req.login(user, (err) => {
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local", { failureRedirect: "/login" })(req, res, () => {
                //user gets redirected if already logged in through cookie auth
                res.redirect("/secrets");
            });
        }
    })

});


app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}.`);
});



