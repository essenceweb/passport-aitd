/**
 * Module dependencies.
 */
var util = require('util'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The AITD authentication strategy authenticates requests by delegating to
 * AITD using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your AITD application's Client ID
 *   - `clientSecret`  your AITD application's Client Secret
 *   - `callbackURL`   URL to which AITD will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'balance', 'transactions', 'request', ...
 *                     (see https://www.aitd.com.au/docs/api/permissions)
 *
 * Examples:
 *
 *     passport.use(new AITDStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/aitd/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://aitd.com.au/oauth2/connect';
  options.tokenURL = options.tokenURL || 'https://www.aitd.com.au/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ' ';

  // Only request the profile if we have the scopes for it
  if(options.scope && options.scope.indexOf('user') < 0) this._skipUserProfile = true;
  this._userProfileURL = options.userProfileURL || 'https://aitd.com.au/rest/whoami';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'aitd';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from AITD.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `aitd`
 *   - `id`               the user's AITD ID
 *   - `displayName`      the user's full name
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body),
          user = json.user;

      var profile = { provider: 'aitd' };
      profile.firstname = user.person_name.firstname;
      profile.lastname = user.person_name.lastname;
      profile.email =  user.mail;

      profile._raw = body;
      profile._json = user;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
