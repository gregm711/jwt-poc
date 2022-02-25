from flask import Flask
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp

class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id

users = [
    User(1, 'user1', 'abcxyz'),
    User(2, 'user2', 'abcxyz'),
]

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}

def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user

def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'super-secret'

jwt = JWT(app, authenticate, identity)

@app.route('/protected')
@jwt_required()
def protected():
    return '%s' % current_identity

@app.route('/jwk')
def jwk():
    return {
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "Lq5Jn4sCh1yIksPD4ea_3OJdMQveXjgOZpXjqBkdXPc",
      "n": "41u5hMmajpaGxL-h5TRjzrvNKQDcu-gU9uboIL5IqGCL8XTxIBvMLMCGJzodP6T8xaNPAMzNhyJkvYa02kaDagzo1asmyfInC8xoMOL9-Rij_R0cBw4-VLX9tca8nphYBRf0C-71DKvSXsjRL0I73Vd3A_IsU03HX7HPbjCt4WNSrfXcvpiEwu5v6-O55dLwpziudHleTdBh3NBYceyo783pU2coyFvVNRYyk-0MJps1qrsvUu7Jpl_IqVviDrUW-qDM7KhH816YAf5TnlAZ3A-46nMSS9305Y6agl4or6xUkYe73MJVBRXAKpJX7VhbNa2VJDutaW82L6jRJCed6Q",
      "alg": "RS256"
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "JmQIGZ47i4i60gVpTupyVN8Vs6IBhBKEctoQkZu3l6Y",
      "n": "lUTKMbGwjXHwrFQD2_izNrmYrY2aa8qIP4q90TwDJDI4xbctymDhCBPTowh5xtrT0BdhQkrHnh1HGMDXZbkr_SpFvwGBjvOTTyHUS4JSJGwhglSs9CUJFwhFxS8nNWKEEWlDKUI5v3lqfQS-S9iqrd3Y-OAOJPe3FDmmwLX2NMlQLQxj1DbVIR5UE8paMsoCX46vyh_mEV3m8JPne9oejEYdH6xMOqzGRQut1liCOcQvZbS_7H6FORRKe6VqRLsf0TTAB1Lawo32QX5GUczdicza1yz0QpLmy2YfJ6fu_WYAU9BS27xgZbslCifR1ZrLelrf1TS9JwKBcBUZ5Yn-DQ",
      "alg": "RS256"
    },
  ]
    }

if __name__ == '__main__':
    app.run(port=5008)