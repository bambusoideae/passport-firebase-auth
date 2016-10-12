# passport-firebase-auth
Firebase Strategy base on firebase authentication


You must call firebase.initializeApp before use this Strategy.

## Install

    $ npm install passport-firebase-auth

## Usage

#### Create an Application

Before using `passport-firebase-auth`, you must register an application with
Firebase.  If you have not already done so, a new project can be created in the
[Firebase Developers Console](https://console.firebase.google.com/).

#### Configure Strategy

The Firebase authentication strategy authenticates users using a Firebase Token.

You must call  


     firebase.initializeApp({
         serviceAccount: "path/to/serviceAccountCredentials.json",
         databaseURL: "https://databaseName.firebaseio.com"
     });

     
 before using this strategy.
   

    var FirebaseStrategy = require('passport-firebase-auth').Strategy;

    passport.use(new FirebaseStrategy({
        firebaseProjectId: "project-id",
        authorizationURL: 'https://account.example.net/auth',
        callbackURL: 'https://www.example.net/auth/firebase/callback'
      },
      function(accessToken, refreshToken, decodedToken, cb) {
        User.findOrCreate(..., function (err, user) {
          return cb(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'firebaseauth'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/firebase',
      passport.authenticate('firebaseauth', { }));

    app.get('/auth/firebase/callback', 
      passport.authenticate('firebaseauth', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples



## License

[The MIT License](http://opensource.org/licenses/MIT)

