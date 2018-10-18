from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Coffeeshop, Base, MenuItem, User

engine = create_engine('sqlite:///coffeeshopmenu.db')
#bind engine to metadata
Base.metadata.bind = engine 
DBSession = sessionmaker(bind=engine)
session = DBSession()

#create example user
#User1 = User(name='admin', email='ballerifico442@gmail.com')
#session.add(User1)
#session.commit()

#Menu for Ted's Coffee House
coffeeshop1 = Coffeeshop(name="Ted's Coffee House")
session.add(coffeeshop1)
session.commit()

menuItem1 = MenuItem(name='Caffe Latte',description='coffee with milk', price="$2.45", mixture='Hot', coffeeshop=coffeeshop1)
session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(name='Frapuccino', 
	description='coffee blended with ice', price="$4.99", mixture='Blended',coffeeshop=coffeeshop1)
session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(name="Iced Coffee", 
	description='regular coffee on top of ice', price="$2.75", mixture='Cold', coffeeshop=coffeeshop1)
session.add(menuItem3)
session.commit()

#Menu for 734 Coffee
coffeeshop2 = Coffeeshop(name='734 Coffee')
session.add(coffeeshop2)
session.commit()

menuItem1 = MenuItem(name="Espresso", 
	description='double shop of dark roast coffee', price='$4.25', mixture='Hot', coffeeshop=coffeeshop2)
session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(name="Pumpkin Spice Latte", 
	description='pumpkin spice flavored latte', price='$7.45',mixture='Hot', coffeeshop=coffeeshop2)
session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(name="Chai Latte", 
	description='chai flavored latte', price="$3.95",mixture='Hot', coffeeshop=coffeeshop2)
session.add(menuItem3)
session.commit()

print "Added menu Items"