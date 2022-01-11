from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users-portfolio"
BOATS = "boats-portfolio"
LOADS = "loads-portfolio"

# Update the values of the following 3 variables
CLIENT_ID = 'llKH5TKbWYO9otOqhd2rsBTJdCpyKh7C'
CLIENT_SECRET = 'e2oOQCSHcBxbK2_xTlQrb71t_-MyXTehE1ApZTGWrp2XeNduyFmeELVTgkk_rEnZ'
DOMAIN = 'portfolio-macandok-493-f21.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)








@app.route('/')
def index():
    return render_template('index.html')




# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    hack_the_user_haha = auth0.authorize_access_token()

    jwt_for_display = hack_the_user_haha["id_token"]

    resp = auth0.get('userinfo')
    userinfo = resp.json()
    userinfo['userID'] = userinfo['sub']
    userinfo['uniqueID'] = userinfo['sub']

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    session['display_jwt'] = jwt_for_display


    
    new_user = datastore.entity.Entity(key=client.key(USERS))

    query = client.query(kind=USERS)
    results = list(query.fetch())

    userAlreadyExists = False
    for e in results:
        if e["userID"] == userinfo['sub']:
            userAlreadyExists = True

    if userAlreadyExists == False:
        new_user.update({"userID": userinfo['sub'], "email": userinfo['email'], "boats": []})
        client.put(new_user)



    return redirect('/dashboard')





@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='https://portfolio-macandok.wl.r.appspot.com/callback')




# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers1 = { 'content-type': 'application/json' }
    url1 = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url1, json=body, headers=headers1)
    r = r.json()

    # print(r)


    headers2 = {'Authorization': 'Bearer {}'.format(r["id_token"])}
    url2 = 'https://portfolio-macandok.wl.r.appspot.com/decode'
    payload = requests.get(url2, headers=headers2)
    payload = payload.json()
    payload["id_token"] = r["id_token"]

    # print(payload)


    new_user = datastore.entity.Entity(key=client.key(USERS))

    query = client.query(kind=USERS)
    results = list(query.fetch())

    userAlreadyExists = False
    for e in results:
        if e["userID"] == payload['sub']:
            userAlreadyExists = True

    if userAlreadyExists == False:
        new_user.update({"userID": payload['sub'], "email": payload['email'], "boats": []})
        client.put(new_user)



    return (payload, 201)





def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)

  return decorated





@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4), userinfo_jwt=session['display_jwt'])





@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': "https://portfolio-macandok.wl.r.appspot.com/login", 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))









# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request, isForMyErrorResponse):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:

        if isForMyErrorResponse:
            return False


        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:

            if isForMyErrorResponse:
                return False


            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)





# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request, False)
    return (payload, 201)          
        












@app.route('/delete-all-users', methods=['DELETE'])
def delusers():

    if request.method == 'DELETE':

        q = client.query(kind=USERS)
        l = list(q.fetch())
        for i in l:
            key = client.key(USERS, int(i.key.id))
            user = client.get(key=key)
            client.delete(user)

        query = client.query(kind=USERS)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id

        return (jsonify(results), 204)


@app.route('/delete-all-boats', methods=['DELETE'])
def delboats():

    if request.method == 'DELETE':

        q = client.query(kind=BOATS)
        l = list(q.fetch())
        for i in l:
            key = client.key(BOATS, int(i.key.id))
            boat = client.get(key=key)
            client.delete(boat)

        query = client.query(kind=BOATS)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id

        return (jsonify(results), 204)


@app.route('/delete-all-loads', methods=['DELETE'])
def delloads():

    if request.method == 'DELETE':

        q = client.query(kind=LOADS)
        l = list(q.fetch())
        for i in l:
            key = client.key(LOADS, int(i.key.id))
            load = client.get(key=key)
            client.delete(load)

        query = client.query(kind=LOADS)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id

        return (jsonify(results), 204)




@app.route('/get-all-boats', methods=['GET'])
def boats_get_all():

    if request.method == 'GET':
        query = client.query(kind=BOATS)
        results = list(query.fetch())
        for e in results:
            e["id"] = int(e.key.id)
            e["self"] = request.url_root + "boats/" + str(e.key.id)
        return (jsonify(results), 200)








def get_user_from_datastore(sub):

    query = client.query(kind=USERS)
    results = list(query.fetch())
    for e in results:
        if e["userID"] == sub:
            userID = e.key.id
    user_key = client.key(USERS, int(userID))
    user = client.get(key=user_key)

    return user



def check_if_boat_name_already_exists(name):

    query = client.query(kind=BOATS)
    results = list(query.fetch())
    for e in results:
        if e["name"] == name:
            return True
    return False






















@app.route('/users', methods=['GET', 'POST'])
def users_get_post():


    if request.method == 'GET':
        query = client.query(kind=USERS)
        results = list(query.fetch())

        for p in results:

            if p["boats"]:
                for b in p["boats"]:
                    b["self"] = request.url_root + "boats/" + str(b["boat_id"])


        return (jsonify(results), 200)



    elif request.method == 'POST':

        content = request.get_json()

        new_user = datastore.entity.Entity(key=client.key(USERS))

        query = client.query(kind=USERS)
        results = list(query.fetch())
        for e in results:
            if e["userID"] == content["userID"]:
                return

        new_user.update({"userID": content["userID"]})
        client.put(new_user)

        return (new_user, 201)

    else:
        return ('', 405)



























@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():

    if request.method == 'POST':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()


        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:

            if not content:
                return ({ "Error": "Request cannot be empty" }, 400)

            if ("name" not in content) or ("type" not in content) or ("length" not in content):
                return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)

            if check_if_boat_name_already_exists(content["name"]):
                return ({ "Error": "The name of the boat already exists" }, 403)

            new_boat = datastore.entity.Entity(key=client.key(BOATS))

            new_boat.update({
                "name": content["name"], 
                "type": content["type"],
                "length": content["length"],
                "userID": payload["sub"],
                "userEmail": payload["email"],
                "loads": []
            })

            client.put(new_boat)

            new_boat["id"] = int(new_boat.key.id)
            new_boat["self"] = request.url_root + "boats/" + str(new_boat.key.id)


            user = get_user_from_datastore(payload["sub"])
            
            user["boats"].append({"boat_id": new_boat["id"], "boat_name": new_boat["name"]})
            client.put(user)



            return (new_boat, 201)

        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)




    elif request.method == 'GET':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)
        

        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:


            numItems = 0

            query_for_counting = client.query(kind=BOATS)
            results_for_counting = list(query_for_counting.fetch())

            for e in results_for_counting:
                if e["userID"] == payload["sub"]:
                    numItems += 1


            query = client.query(kind=BOATS)
            query.add_filter("userID", "=", payload["sub"])
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            query_iter = query.fetch(limit= q_limit, offset=q_offset)

            pages = query_iter.pages

            items = list(next(pages))

            if query_iter.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None



            results = items



            for e in results:

                e["id"] = e.key.id
                e["self"] = request.url_root + "boats/" + str(e.key.id)

                if e["loads"]:
                    for load in e["loads"]:
                        load["self"] = request.url_root + "loads/" + str(load["id"])




            output = {"items": results, "Number of Total Items": numItems}

            if next_url:
                output["next"] = next_url


            return (jsonify(output), 200)
                




        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)



    else:
        return ('', 405)





@app.route('/boats/<boat_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def get_put_patch_delete_a_boat(boat_id):


    if request.method == 'GET':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:

            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if not boat:
                return ({ "Error": "No boat with this boat_id exists" }, 404)



            if boat["userID"] == payload["sub"]:

                boat["id"] = int(boat.key.id)
                boat["self"] = request.url_root + "boats/" + str(boat.key.id)

                if boat["loads"]:
                    for l in boat["loads"]:
                        l["self"] = request.url_root + "loads/" + str(l["id"])

                return (boat, 200)

            else:
                return ({ "Error": "boat_id is owned by someone else" }, 403)



        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)



    elif request.method == 'DELETE':


        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:

            query = client.query(kind=BOATS)
            results = list(query.fetch())

            for e in results:

                if int(e.key.id) == int(boat_id) and e["userID"] == payload["sub"]:

                    boat_key = client.key(BOATS, int(e.key.id))
                    boat = client.get(key=boat_key)



                    loads_ids = []

                    for a_load in boat["loads"]:
                        loads_ids.append(a_load["id"])

                    for load_id in loads_ids:

                        load_key = client.key(LOADS, int(load_id))
                        load = client.get(key=load_key)

                        if load:
                            load["carrier"] = {}
                            client.put(load)




                    client.delete(boat)






                    user = get_user_from_datastore(payload["sub"])

                    for a_boat in user["boats"]:
                        if a_boat["boat_id"] == int(boat_id):
                            user["boats"].remove(a_boat)
                    
                    client.put(user)





                    return ('', 204)

                elif int(e.key.id) == int(boat_id) and e["userID"] != payload["sub"]:

                    return ({ "Error": "boat_id is owned by someone else" }, 403)


            return ({ "Error": "no boat with this boat_id exists" }, 404)

        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)



    elif request.method == 'PATCH':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()


        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:

            if not content:
                return ({ "Error": "Request cannot be empty" }, 400)


            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if not boat:
                return ({ "Error": "No boat with this boat_id exists" }, 404)


            if boat["userID"] == payload["sub"]:


                supported_attributes = ["name", "type", "length"]
                for key, val in content.items():
                    if key not in supported_attributes:
                        return ({ "Error": "We do not support attributes other than name, type, and length" }, 400)

                
                if check_if_boat_name_already_exists(content["name"]):
                    return ({ "Error": "The name of the boat already exists" }, 403)



                if ("name" in content) and ("type" in content) and ("length" in content):
                    boat.update({ "name": content["name"], "type": content["type"], "length": content["length"] })


                elif ("name" in content) and ("type" in content):
                    boat.update({ "name": content["name"], "type": content["type"] })

                elif ("type" in content) and ("length" in content):
                    boat.update({ "type": content["type"], "length": content["length"] })

                elif ("name" in content) and ("length" in content):
                    boat.update({ "name": content["name"], "length": content["length"] })


                elif "name" in content:
                    boat.update({ "name": content["name"] })
                
                elif "type" in content:
                    boat.update({ "type": content["type"] })
                    
                elif "length" in content:
                    boat.update({ "length": content["length"] })
                

                else:
                    return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)




                client.put(boat)

                boat["id"] = int(boat.key.id)
                boat["self"] = request.url_root + "boats/" + str(boat.key.id)

                if boat["loads"]:
                    for l in boat["loads"]:
                        l["self"] = request.url_root + "loads/" + str(l["id"])



                user = get_user_from_datastore(payload["sub"])

                for i in user["boats"]:
                    if i["boat_id"] == boat["id"]:
                        i["boat_name"] = boat["name"]
                
                client.put(user)



                return (boat, 200)


            else:
                return ({ "Error": "boat_id is owned by someone else" }, 403)

        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)





    elif request.method == 'PUT':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()


        payload = verify_jwt(request, isForMyErrorResponse=False)

        if payload:

            if not content:
                return ({ "Error": "Request cannot be empty" }, 400)

            if ("name" not in content) or ("type" not in content) or ("length" not in content):
                return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)

            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            if not boat:
                return ({ "Error": "No boat with this boat_id exists" }, 404)

            
            if boat["userID"] == payload["sub"]:


                supported_attributes = ["name", "type", "length"]
                for key, val in content.items():
                    if key not in supported_attributes:
                        return ({ "Error": "We do not support attributes other than name, type, and length" }, 400)


                if check_if_boat_name_already_exists(content["name"]):
                    return ({ "Error": "The name of the boat already exists" }, 403)



                boat.update({ "name": content["name"], "type": content["type"], "length": content["length"] })
                client.put(boat)

                boat["id"] = int(boat.key.id)
                boat["self"] = request.url_root + "boats/" + str(boat.key.id)

                if boat["loads"]:
                    for l in boat["loads"]:
                        l["self"] = request.url_root + "loads/" + str(l["id"])


                user = get_user_from_datastore(payload["sub"])
                
                for i in user["boats"]:
                    if i["boat_id"] == boat["id"]:
                        i["boat_name"] = boat["name"]

                client.put(user)


                return (boat, 200)


            else:
                return ({ "Error": "boat_id is owned by someone else" }, 403)

        else:

            return ({ "Error": "Missing or Invalid JWT" }, 401)





    else:
        return 'Method not recognized'



            



































@app.route('/loads', methods=['POST','GET'])
def loads_post_get(cursor=None):

    if request.method == 'POST':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()

        if not content:
            return ({ "Error": "Request cannot be empty" }, 400)

        if ("content" not in content) or ("volume" not in content) or ("creation_date" not in content):
            return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)

        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update({"content": content["content"], "volume": content["volume"], "creation_date": content["creation_date"], "carrier": {}})
        client.put(new_load)

        new_load["id"] = new_load.key.id
        new_load["self"] = request.url_root + "loads/" + str(new_load.key.id)


        return (new_load, 201)



    elif request.method == 'GET':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        query_for_counting = client.query(kind=LOADS)
        results_for_counting = list(query_for_counting.fetch())

        numItems = len(results_for_counting)


        query = client.query(kind=LOADS)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        query_iter = query.fetch(limit= q_limit, offset=q_offset)

        pages = query_iter.pages

        items = list(next(pages))

        if query_iter.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None


        for item in items:
            item["id"] = item.key.id
            item["self"] = request.url_root + "loads/" + str(item.key.id)

            if item["carrier"]:
                item["carrier"]["self"] = request.url_root + "boats/" + str(item["carrier"]["id"])
                


        output = {"items": items, "Number of Total Items": numItems}

        if next_url:
            output["next"] = next_url


        return (jsonify(output), 200)


    else:
        return ('', 405)










@app.route('/loads/<id>', methods=['DELETE','GET','PUT','PATCH'])
def loads_delete_get_put_patch(id):

    if request.method == 'GET':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if not load:
            return ({ "Error": "No load with this load_id exists" }, 404)

        load["id"] = load.key.id
        load["self"] = request.url_root + "loads/" + str(load.key.id)


        if load["carrier"]:
            load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])


            boat_key = client.key(BOATS, int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)

            if not boat:
                return ({ "Error": "No boat with this boat_id exists" }, 404)

            load["carrier"]["name"] = boat["name"]



        return (load, 200)


    elif request.method == 'DELETE':

        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if not load:
            return ({ "Error": "No load with this load_id exists" }, 404)


        if load["carrier"]:
            boat_key = client.key(BOATS, int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)

            if boat:
                for a_load in boat["loads"]:
                    if a_load["id"] == int(id):
                        boat["loads"].remove(a_load)

                client.put(boat)


        client.delete(load_key)

            
        return ('', 204)




    elif request.method == 'PATCH':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()

        if not content:
            return ({ "Error": "Request cannot be empty" }, 400)


        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if not load:
            return ({ "Error": "No load with this load_id exists" }, 404)


        supported_attributes = ["content", "volume", "creation_date"]
        for key, val in content.items():
            if key not in supported_attributes:
                return ({ "Error": "We do not support attributes other than content, volume, and creation_date" }, 400)


        if ("content" in content) and ("volume" in content) and ("creation_date" in content):
            load.update({ "content": content["content"], "volume": content["volume"], "creation_date": content["creation_date"] })


        elif ("content" in content) and ("volume" in content):
            load.update({ "content": content["content"], "volume": content["volume"] })

        elif ("volume" in content) and ("creation_date" in content):
            load.update({ "volume": content["volume"], "creation_date": content["creation_date"] })

        elif ("content" in content) and ("creation_date" in content):
            load.update({ "content": content["content"], "creation_date": content["creation_date"] })


        elif "content" in content:
            load.update({ "content": content["content"] })
        
        elif "volume" in content:
            load.update({ "volume": content["volume"] })
            
        elif "creation_date" in content:
            load.update({ "creation_date": content["creation_date"] })
        

        else:
            return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)




        client.put(load)

        load["id"] = int(load.key.id)
        load["self"] = request.url_root + "loads/" + str(load.key.id)

        if load["carrier"]:
            load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])


        return (load, 200)






    elif request.method == 'PUT':

        if request.headers['Accept'] != "application/json":
            return ({ "Error": "Accept header must have application/json" }, 406)


        content = request.get_json()


        if not content:
            return ({ "Error": "Request cannot be empty" }, 400)

        if ("content" not in content) or ("volume" not in content) or ("creation_date" not in content):
            return ({ "Error": "The request object is missing at least one of the required attributes" }, 400)

        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if not load:
            return ({ "Error": "No load with this boat_id exists" }, 404)


        supported_attributes = ["content", "volume", "creation_date"]
        for key, val in content.items():
            if key not in supported_attributes:
                return ({ "Error": "We do not support attributes other than content, volume, and creation_date" }, 400)



        load.update({ "content": content["content"], "volume": content["volume"], "creation_date": content["creation_date"] })
        client.put(load)

        load["id"] = int(load.key.id)
        load["self"] = request.url_root + "loads/" + str(load.key.id)

        if load["carrier"]:
            load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])


        return (load, 200)




    else:
        return 'Method not recognized'




















@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT','DELETE'])
def boat_load_put_delete(boat_id, load_id):

    if request.method == 'PUT':

        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)

        if (not boat) or (not load):
            return ({ "Error": "The specified boat and/or load does not exist" }, 404)

        if load["carrier"]:
            return ({ "Error": "The load is already assigned to a boat" }, 403)


        boat["loads"].append({"id": load.key.id, "content": load["content"]})
        client.put(boat)

        load["carrier"] = {"id": boat.key.id, "name": boat["name"]}
        client.put(load)


        return ('', 204)


    elif request.method == 'DELETE':

        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)


        if (not boat) or (not load):
            return ('{ "Error": "No load with this load_id is in the boat with this boat_id" }', 404)

        load_existed = False

        for a_load in boat["loads"]:
            if a_load["id"] == int(load_id):
                boat["loads"].remove(a_load)
                load_existed = True

        if load_existed == False:
            return ('{ "Error": "No load with this load_id is in the boat with this boat_id" }', 404)

        client.put(boat)


        load["carrier"] = {}
        client.put(load)


        return ('', 204)


    else:
        return 'Method not recognized'




































if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

