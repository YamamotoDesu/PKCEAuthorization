# PKCEAuthorization
Dissect the PKCE Authorization Code Grant Flow on iOS

## Authorization Code Grant Flow
### This diagram represents the OAuth 2.0 Authorization code grant flow that mobile applications implement:
![image](https://user-images.githubusercontent.com/47273077/224520620-83d29396-a6f8-46af-a407-cd600b8ce67a.png)

1. The user starts the login flow by tapping the MyGoogleInfo Login button.

2. Consequently, the app asks the authorization server to identify the user and ask their consent to access the data. The request includes a client_id so that the server can identify the app requesting the access.

3. So, the authorization server redirects the user to its login screen (e.g. Google) and asks the user’s consent to give the app access to the API.

4. The user logs in and approves the request.

5. If the user approves the access, the authorization server returns a grant code to the client.

6. The client requests a token to the authorization server, passing its client_id and the received grant code.

7. In response, the authorization server emits a token after verifying the client_id and the grant code.

8. Finally, the client accesses the data to the resource server, authenticating its requests with the token.

### The following diagram depicts how PKCE strengthens the Authorization Code Grant flow in practice:
![image](https://user-images.githubusercontent.com/47273077/224521025-b35a8707-8dd9-4836-90ec-7831c24a7921.png)

1. This is where the login flow begins.

2. On each login request, the client generates a random code (code_verifier) and derives a code_challenge from it.

3. When starting the flow, the client includes the code_challenge in the request to the authorization server. On receiving the authorization request, the authorization server saves this code for later verification.

7. The client sends the code_verifier when requesting an access token.

8. Therefore, the authorization server verifies that code_verifier matches code_challenge. If these two codes match, the server knows the client is legit and emits the token.
