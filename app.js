import express from "express";
import bodyParser from "body-parser";
import mongoose, { Schema } from "mongoose";
import 'dotenv/config';
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

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
    password: String,
    googleId: String,   
    secret: [String]
});


//using this plugin to hash and salt passwords and save users to mongoDB database
userSchema.plugin(passportLocalMongoose);

//collection for all users
const User = mongoose.model("User", userSchema);

//config passport and passport local strategy for mongoose
passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});


//Config for google auth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    async function (accessToken, refreshToken, profile, cb) {
        try {
            // check User collection for anyone with a google ID of profile.id
            let user = await User.findOne({ googleId: profile.id });

            if (!user) {
                // No user was found. Create a new user with values from Google 
                user = new User({
                    email: profile.email,
                    username: profile.username,
                    googleId: profile.id,
                    provider: "google",
                    google: profile._json
                });

                await user.save();
            }
            // Found user. Return
            return cb(null, user);
        } catch (err) {
            return cb(err);
        }
    }
));

app.get("/", (req, res) => {
    res.render("home.ejs");
});

//Authenticating requests using passport google strategy
//Auth on google servers asking for users profile once they logged in. Once successful, google will redirect to "/auth/google/secrets"
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] }));


//Here we authenticate locally and save session
app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets page.
        res.redirect("/secrets");
    });

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/secrets", async (req, res) => {
    try {
        const usersWithSecrets = await User.find({secret: {$ne:null} }); //returns array of user secrets
        res.render("secrets.ejs", {
            allUserSecrets: usersWithSecrets
        });
    } catch (error) {
        console.log(error);
    }
    
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
})

app.post("/submit", async (req, res) => {
    try {
        const submittedSecret = req.body.secret;
        const userId = req.user.id;
        //a single user can submit more than one secret so we want to push the update into a secrets array associated with the user
        const userUpdateSecret = await User.findByIdAndUpdate(userId, {$push: { secret: submittedSecret }});
        userUpdateSecret.save();
        res.redirect("/secrets");
    } catch (error) {
        console.log(error);
    }
})

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        } else {
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
        if (err) {
            console.log(err);
        } else {
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



