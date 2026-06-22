// Single shared csurf middleware instance.
//
// Previously every route file created its own csurf() instance. They all read and
// write the same session secret (req.session.csrfSecret), so sharing one instance
// keeps token generation/verification consistent and avoids subtle divergence.
// The "random / after-idle invalid csrf token" fix also relies on a shared session
// store + a shared SESSION_SECRET across instances (see app.js) and the global
// EBADCSRFTOKEN error handler that lets the client recover with a fresh token.
module.exports = require('csurf')();
