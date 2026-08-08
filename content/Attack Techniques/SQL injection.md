# What is SQL injection (SQLi)
- SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
- https://youtu.be/wX6tszfgYp4
## ## Retrieving hidden data
- ```https://insecure-website.com/products?category=Gifts'--```
- Resulting SQL query:
	- ```SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1```
- The key thing here is that the double-dash sequence `--` is a comment indicator in SQL, and means that the rest of the query is interpreted as a comment. This effectively removes the remainder of the query, so it no longer includes `AND released = 1`. This means that all products are displayed, including unreleased products.
- Going further, an attacker can cause the application to display all the products in any category, including categories that they don't know about:
	- ```https://insecure-website.com/products?category=Gifts'+OR+1=1--```
- This results in the SQL query:
	- ````SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1````
- The modified query will return all items where either the category is Gifts, or 1 is equal to 1. Since `1=1` is always true, the query will return all items.

### Subverting application logic
- Application checks the credentials by performing the following SQL query:
	- ````SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'````
- If the query returns the details of a user, then the login is successful.
- Here, an attacker can log in as any user without a password simply by using the SQL comment sequence `--` to remove the password check from the `WHERE` clause of the query. For example, submitting the username `administrator'--` and a blank password results in the following query:
	- ````SELECT * FROM users WHERE username = 'administrator'--' AND password = ''````
	- This query returns the user whose username is `administrator` and successfully logs the attacker in as that user.
### Retrieving data from other database tables
- 