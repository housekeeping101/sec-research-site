https://www.youtube.com/watch?v=996OiexHze0
oktadev
Oauth 2.0 Terminology:
- Resource owner
	- User, owns the data the application wants to get to
- Client
	- Application that wants to get to the db
- Authorization server
	- System used to authorize the permission
- Resource server
	- API or system that holds the data client wants to get to
	- Authorization server and Resource server can be the same system
- Authorization grant
	- Thing that proves user has consented
- Redirect URI
	- Where authorization server redirects back to 
- Access token
	- Key used to get into resource server to do specific thing
- https://speakerdeck.com/nbarbettini/oauth-and-openid-connect-in-plain-english?slide=10
- Authorization server has list of scopes it understands
	- levels or list of permissions
	- Client application requests scope needed
	- Handles login, security and sessions
- Oauth 2.0 flows
	- Authorization code (front channel + back channel)
	- Implicit (front channel only)
	- Resource owner password credentials (back channel only)
	- Client credentials (back channel only)
- Oauth should be used for authorization not authentication
	- designed for permission, scopes
- Open ID Connect:
	- Extension of Oauth 2.0 to solve authentication issues
- What OpenID Connect adds:
	- ID token
		- JWT
	- UserInfo endpoing for getting more user info
	- standard set of scopes
	- Standardized implementation

Identity user cases:
- Simple login (OpenID Connect) - Authentication
- Single sign-on accross sites (OpenID Connect) - Authentication
- Mobile app login (OpenID Connect) - Authentication
- Delegated authorization (OAuth 2.0) - Authorization

- OAuth and OpenID Connect
	- OAuth:
		- Granting access to API
		- Getting access to user data in other systems
		- Authorization
	- OpenID Connect:
		- Logging the user in
		- Making you accounts available in other systems
		- Authentication