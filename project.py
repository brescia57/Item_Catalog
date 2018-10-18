#!/usr/bin/python
import sys
from flask import Flask, render_template, url_for, request, abort, g
from flask import redirect, flash, jsonify, make_response
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker, relationship
from database_setup import Base, Coffeeshop, MenuItem, User
from flask import session as login_session
import menus
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
import requests
import httplib2

app = Flask(__name__)

#Google client_id

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Coffee Shop Menu Application'

#connect to database
engine = create_engine('sqlite:///coffeeshopmenu.db')
Base.metadata.bind = engine 

#Create session
DBSession = sessionmaker(bind=engine)
session = DBSession()

#Create a State Token to prevent forgery
@app.route("/login")
def showLogin():
    state = "".join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session["state"] = state
    return render_template("login.html", STATE=state)
    #return "The current session state is %s" % login_session['state']


#GConnect

@app.route('/gconnect', methods=['POST'])
def gconnect():
	#validate token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
		#obtain authorization codes
		code = request.data 

		try:
			#upgrade the authorization code into a credentials object
			oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
			oauth_flow.redirect_uri = 'postmessage'
			credentials = oauth_flow.step2_exchange(code)
		except FlowExchangeError:
			response = make_response(
				json.dumps("Failed to upgrade the authorization code."), 401)
			response.headers["Content-Type"] = 'application/json'
			return response 

		#Check that access token is valid.
		access_token = credentials.access_token
		url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s" % access_token)
		h = httplib2.Http()
		result = json.loads(h.request(url, 'GET')[1])
		#If there is an error, abort
		if result.get('error') is not None:
			response = make_response(json.dumps(result.get('error')), 500)
			response.headers['Content-Type'] = 'application/json'
			return response

		#Verify that the access token is used for the intended user
        gplus_id = credentials.id_token["sub"]
        if result["user_id"] != gplus_id:
            response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401
            )
            response.headers["Content-Type"] = "application/json"
            return response

        #Verify that the access token is valid for this app
        if result['issued_to'] != CLIENT_ID:
        	response = make_response(
        		json.dumps("Token's client ID does not match app's"), 401)
        	print "Token's client ID does not match up."
        	response.headers['Content-Type'] = 'application/json'
        	return response

        stored_access_token = login_session.get("access_token")
        stored_gplus_id = login_session.get("gplus_id")
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps("Current user is already connected."), 200)
            response.headers["Content-Type"] = "application/json"
            return response

        #store the access token in the session for later use
        login_session["access_token"] = credentials.access_token
        login_session["gplus_id"] = gplus_id

        #get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {"access_token": credentials.access_token, "alt": "json"}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json

        login_session["username"] = data["name"]
        login_session["picture"] = data["picture"]
        login_session["email"] = data["email"]

        #Add Provider to Login Session

        login_session['provider'] = 'google'

        #see if user exists, if it doesn't make a new user
        user_id = getUserID(login_session["email"])
        if not user_id:
            user_id = createUser(login_session)
        login_session["user_id"] = user_id

        output = ""
        output += "<h1>Welcome, "
        output += login_session["username"]
        output += "!<h1>"
        output += "<img src='"
        output += login_session["picture"]
        output += "'style = 'width: 300px; height: 300px; border-radius: 150px; -moz-border-radius: 150px;'>"
        flash("You are now logged in as %s" % login_session["username"])
        return output



#user Helper Functions
def createUser(login_session):
	newUser = User(name=login_session["username"], email=login_session["email"], picture=login_session["picture"])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session["email"]).one()
	return user.id

def getUserInfo(user_id):
	user = session.query(User).filter_by(id=user_id).one()
	return user

def getUserID(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get("access_token")
    if access_token is None:
        print "Access Token is None"
        response = make_response(json.dumps("Current user is not connected."), 401)
        response.headers["Content-Type"] = "application/json"
        return response
    print "In gdisconnect access token is %s", access_token
    print "User name is: "
    print login_session["username"]
    url = "https://accounts.google.com/oauth2/revoke?token=%s" % login_session["access_token"]
    h = httplib2.Http()
    result = h.request(url, "GET")[0]
    print "result is "
    print result
    if result["status"] == "200":
        del login_session["access_token"]
        del login_session["gplus_id"]
        del login_session["username"]
        del login_session["email"]
        del login_session["picture"]
        response = make_response(json.dumps("Successfully disconnected"), 200)
        response.headers["Content-Type"] = "application/json"
        return response
    else:
        response = make_response(json.dumps("Failed to revoke token for given user"), 400)
        response.headers["Content-Type"] = "application/json"
        return response

# JSON API

@app.route('/coffeeshops/<int:coffeeshop_id>/menu/JSON')
def coffeeshopMenuJSON(coffeeshop_id):
	coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
	items = session.query(MenuItem).filter_by(
		coffeeshop_id=coffeeshop_id).all()
	return jsonify(MenuItems=[i.serialize for i in items])

@app.route('/coffeeshops/<int:coffeeshop_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(coffeeshop_id, menu_id):
	menuItem = session.query(MenuItem).filter_by(id=menu_id).one()
	return jsonify(menuItem=menuItem.serialize)

@app.route('/coffeeshops/JSON')
def coffeeshopsJSON():
	coffeeshops = session.query(Coffeeshop).all()
	return jsonify(coffeeshops=[r.serialize for r in coffeeshops])


#Show all coffeeshops
@app.route('/')
@app.route('/coffeeshops/')
def showCoffeeshops():
	coffeeshops = session.query(Coffeeshop).order_by(asc(Coffeeshop.name))
	return render_template('coffeeshops.html', coffeeshops=coffeeshops)
	#state = state
	#if "username" not in login_session:
	#	return render_template('coffeeshops.html', coffeeshops=coffeeshops)
	#else:
		#return render_template('coffeeshops.html', coffeeshops=coffeeshops)

#Create coffeeshops
@app.route('/coffeeshops/new/', methods=['GET', 'POST'])
def newCoffeeshop():
	#if 'username' not in login_session:
	#	return redirect('/login')
	if request.method == 'POST':
		#newCoffeeshop = Coffeeshop(name=request.form['name'], user_id=login_session["user_id"])
		newCoffeeshop = Coffeeshop(name=request.form['name'])
		session.add(newCoffeeshop)
		flash("New Coffeeshop %s Successfully Created" % newCoffeeshop.name)
		session.commit()
		return redirect(url_for('showCoffeeshops'))
	else:
		return render_template('newCoffeeshop.html')

#Edit coffeeshop
@app.route('/coffeeshops/<int:coffeeshop_id>/edit/', methods=['GET', 'POST'])
def editCoffeeshop(coffeeshop_id):
	editedCoffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if editedCoffeeshop.user_id != login_session['user_id']:
		return "<script>{alert('Unauthorized');}</script>"
	if request.method == 'POST':
		if request.form['name']:
			editedCoffeeshop.name = request.form['name']
			flash('Coffeeshop Successfully Edited %s' % editedCoffeeshop.name)
			return redirect(url_for('showCoffeeshops'))
		else:
			return render_template('editCoffeeshop.html', coffeeshop=editedCoffeeshop)

#Delete coffeeshop
@app.route('/coffeeshops/<int:coffeeshop_id>/delete/', methods=['GET', 'POST'])
def deleteCoffeeshop(coffeeshop_id):
	coffeeshopToDelete = session.query(
		Coffeeshop).filter_by(id=coffeeshop_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if coffeeshopToDelete.user_id != login_session['user_id']:
		return "<script>{alert('Unauthorized');}</script>"
	if request.method == 'POST':
		session.delete(coffeeshopToDelete)
		flash('%s Successfully Deleted' % coffeeshopToDelete.name)
		session.commit()
		return redirect(url_for('showCoffeeshops', coffeeshop_id=coffeeshop_id))
	else:
		return render_template('deleteCoffeeshop.html', coffeeshop=coffeeshopToDelete)

#Show coffeeshop menu
@app.route('/coffeeshops/<int:coffeeshop_id>/')
@app.route('/coffeeshops/<int:coffeeshop_id>/menu/')
def coffeeshopMenu(coffeeshop_id):
	coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
	creator = getUserInfo(coffeeshop.user_id)
	items = session.query(
		MenuItem).filter_by(coffeeshop_id=coffeeshop_id).all()
	return render_template('menu.html', coffeeshop=coffeeshop, items=items, creator=creator)

#Create new menu item
@app.route('/coffeeshops/<int:coffeeshop_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(coffeeshop_id):
	if 'username' not in login_session:
		return redirect('/login')
		#session = connect_to_database()
	if login_session['user_id']!= coffeeshop.user_id:
		return "<script>function myFunction() {alert('Unauthorized');}</script><body onload='myFunction()''>"

	if request.method == 'POST':
		newItem = MenuItem(name=request.form['name'],
			description=request.form['description'],
			price=request.form['price'],
			mixture=request.form['mixture'],
			coffeeshop_id=coffeeshop_id)
		session.add(newItem)
		session.commit()
		flash("New Menu %s Item has been added" % (newItem.name))
		return redirect(url_for('coffeeshopMenu', coffeeshop_id=coffeeshop_id))
	else:
		return render_template('newmenuitem.html', coffeeshop_id=coffeeshop_id)
		#return render_template('newmenuitem.html', coffeeshop=coffeeshop)

#Edit Menu item
@app.route('/coffeeshops/<int:coffeeshop_id>/menu/<int:menu_id>/edit/', methods=['GET', 'POST'])
def editMenuItem(coffeeshop_id, menu_id):
	if 'username' not in login_session:
		return redirect('/login')
	editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
	coffeeshop = session.query(Coffeeshop).filter_by(id = coffeeshop_id).one()
	if login_session['user_id'] != coffeeshop.user_id:
		return "<script>function myFunction() {alert('Unauthorized');}</script><body onload='myFunction()''>"
	if request.method == 'POST':
		if request.form['name']:
			editedItem.name = request.form['name']
		if request.form['description']:
			editedItem.description = request.form['description']
		if request.form['price']:
			editedItem.price = request.form['price']
		if request.form['mixture']:
			editedItem.mix = request.form['mixture']
		session.add(editedItem)
		session.commit()
		flash("Menu Item has been edited")

		return redirect(url_for('coffeeshopMenu', coffeeshop_id=coffeeshop_id))
	else:
		return render_template('editedmenuitem.html', coffeeshop_id=coffeeshop_id, menu_id=menu_id, item=editedItem)


#Delete menu item
@app.route('/coffeeshops/<int:coffeeshop_id>/menu/<int:menu_id>/delete/', methods=['GET', 'POST'])
def deleteMenuItem(coffeeshop_id, menu_id):
	coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
	itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if login_session['user_id'] != coffeeshop.user_id:
		return "<script>function myFunction() {alert('Unauthorized');}</script><body onload='myFunction()''>"
	
	if request.method == 'POST':
		session.delete(itemToDelete)
		session.commit()
		flash('Menu Item has been deleted')
		return redirect(url_for('coffeeshopMenu', coffeeshop_id=coffeeshop_id))
	else:
		return render_template('deletemenuitem.html', item=itemToDelete)


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
