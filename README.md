# PKCEAuthorization
Dissect the PKCE Authorization Code Grant Flow on iOS
https://www.kodeco.com/33091327-dissect-the-pkce-authorization-code-grant-flow-on-ios

## Authorization Code Grant Flow
### ✅This diagram represents the OAuth 2.0 Authorization code grant flow that mobile applications implement:
![image](https://user-images.githubusercontent.com/47273077/224520620-83d29396-a6f8-46af-a407-cd600b8ce67a.png)

[1] The user starts the login flow by tapping the MyGoogleInfo Login button.

[2] Consequently, the app asks the authorization server to identify the user and ask their consent to access the data. The request includes a client_id so that the server can identify the app requesting the access.

[3] So, the authorization server redirects the user to its login screen (e.g. Google) and asks the user’s consent to give the app access to the API.

[4] The user logs in and approves the request.

[5] If the user approves the access, the authorization server returns a grant code to the client.

[6] The client requests a token to the authorization server, passing its client_id and the received grant code.

[7] In response, the authorization server emits a token after verifying the client_id and the grant code.

[8] Finally, the client accesses the data to the resource server, authenticating its requests with the token.

### 💀Attacking the Authorization Code Grant Flow

Although the authorization code grant flow is the way to go for mobile apps, it’s subject to client impersonation attacks. A malicious app can impersonate a legitimate client and receive a valid authentication token to access the user data.

For the flow diagram above, to receive a token the attacker should know these two parameters:

The app’s client_id.
The code received in the callback URL from the authorization token.
Under certain circumstances, a malicious app can recover both. The app’s client ID is usually hardcoded, for example, and an attacker could find it by reverse-engineering the app. Or, by registering the malicious app as a legitimate invoker of the callback URL, the attacker can also sniff the callback URL.

Once the attacker knows the client ID and the grant code, they can request a token to the token endpoint. From that point forward, they use the access token to retrieve data illegally.

-----

### ✅The following diagram depicts how PKCE strengthens the Authorization Code Grant flow in practice:
![image](https://user-images.githubusercontent.com/47273077/224521025-b35a8707-8dd9-4836-90ec-7831c24a7921.png)

[1] This is where the login flow begins.

[2] On each login request, the client generates a random code (code_verifier) and derives a code_challenge from it.

[3] When starting the flow, the client includes the code_challenge in the request to the authorization server. On receiving the authorization request, the authorization server saves this code for later verification.

[7] The client sends the code_verifier when requesting an access token.

[8] Therefore, the authorization server verifies that code_verifier matches code_challenge. If these two codes match, the server knows the client is legit and emits the token.

------
PKCECodeGenerator
```swift
import Foundation
import CryptoKit

enum PKCECodeGenerator {
  /// Generate a random code as specified in
  /// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
  static func generateCodeVerifier() -> String {
    // TODO: Generate code_verifier
    // 1
    var buffer = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
    // 2
    return Data(buffer).base64URLEncodedString()
  }

  /// Generate a code challenge from a code verifier as specified in
  /// https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
  static func generateCodeChallenge(codeVerifier: String) -> String? {
    // TODO: Generate code_challenge
    guard let data = codeVerifier.data(using: .utf8) else { return nil }

    let dataHash = SHA256.hash(data: data)
    return Data(dataHash).base64URLEncodedString()
  }
}

private extension Data {
  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
      .trimmingCharacters(in: .whitespaces)
  }
}
```


Generating HTTP Requests
In addition, the standard specifies two different endpoints on the Authorization server for the two authorization phases.

Open PKCERequestBuilder.swift and note the properties for each of these endpoints at the top:

Authorization endpoint at /authorize is in charge of emitting the authorization code grant.
Token endpoint at /token-generation, to emit and refresh tokens.


```swift
import Foundation

struct PKCERequestBuilder {
  private let authorizationEndpointURL: String
  private let tokenEndpointURL: String
  private let clientId: String
  private let redirectURI: String

  // MARK: Authorization
  /// Generates a URL with the required parameters for the authorization endpoint
  /// https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
  func createAuthorizationRequestURL(codeChallenge: String) -> URL? {
    guard var urlComponents = URLComponents(string: authorizationEndpointURL) else { return nil }

    urlComponents.queryItems = [
      URLQueryItem(name: "client_id", value: clientId),
      URLQueryItem(name: "code_challenge", value: codeChallenge),
      URLQueryItem(name: "code_challenge_method", value: "S256"),
      URLQueryItem(name: "access_type", value: "offline"),
      URLQueryItem(name: "redirect_uri", value: redirectURI),
      URLQueryItem(name: "response_type", value: "code"),
      URLQueryItem(name: "scope", value: "openid+profile+https://www.googleapis.com/auth/userinfo.profile")
    ]

    return urlComponents.url
  }

  // MARK: Token
  /// Generates a `URLRequest` for the token exchange
  /// https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
  func createTokenExchangeURLRequest(code: String, codeVerifier: String) -> URLRequest? {
    var urlRequest = createURLRequestForTokenEndpoint()
    urlRequest?.httpBody = createTokenExchangeRequestData(code: code, codeVerifier: codeVerifier)
    return urlRequest
  }

  func createRefreshTokenURLRequest(refreshToken: String) -> URLRequest? {
    var urlRequest = createURLRequestForTokenEndpoint()
    urlRequest?.httpBody = createRefreshTokenRequestData(refreshToken: refreshToken)
    return urlRequest
  }

  private func createURLRequestForTokenEndpoint() -> URLRequest? {
    guard let tokenEndpointURL = URL(string: tokenEndpointURL) else { return nil }

    var urlRequest = URLRequest(url: tokenEndpointURL)
    urlRequest.httpMethod = "POST"
    urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

    return urlRequest
  }

  private func createTokenExchangeRequestData(code: String, codeVerifier: String) -> Data? {
    var urlComponents = URLComponents()

    urlComponents.queryItems = [
      URLQueryItem(name: "grant_type", value: "authorization_code"),
      URLQueryItem(name: "client_id", value: clientId),
      URLQueryItem(name: "code", value: code),
      URLQueryItem(name: "code_verifier", value: codeVerifier),
      URLQueryItem(name: "redirect_uri", value: redirectURI)
    ]

    return urlComponents.query?.data(using: .utf8)
  }

  private func createRefreshTokenRequestData(refreshToken: String) -> Data? {
    var urlComponents = URLComponents()

    urlComponents.queryItems = [
      URLQueryItem(name: "grant_type", value: "refresh_token"),
      URLQueryItem(name: "client_id", value: clientId),
      URLQueryItem(name: "refresh_token", value: refreshToken)
    ]

    return urlComponents.query?.data(using: .utf8)
  }
}

extension PKCERequestBuilder {
  // TODO: Replace clientID with ID from Google
  static let myGoogleInfo = PKCERequestBuilder(
    authorizationEndpointURL: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpointURL: "https://oauth2.googleapis.com/token",
    clientId: "REPLACE_WITH_CLIENTID_FROM_GOOGLE_APP",
    // swiftlint:disable:next force_unwrapping
    redirectURI: "\(Bundle.main.bundleIdentifier!):/oauth2callback"
  )
}
```
🫖 Note:
According to the RFC, the client should communicate with these two endpoints with two different HTTP request types:

Using a GET with all the required parameters passed as URL parameters, for the authorization endpoint.
Sending a POST with the parameters passed in the request’s body, encoded as URL parameters, for the token endpoint.

## 🌝Preparing Server Side (Google Cloud Platform)

### Enabling the Required API
* Enable the Google People API to allow the app to query the user information
![image](https://user-images.githubusercontent.com/47273077/224525276-98d93d41-fd90-4dad-bbb1-cf4a3fd1a2bf.png)

* Then, search for Google People API and click ENABLE.
![image](https://user-images.githubusercontent.com/47273077/224525294-eea4e87d-07b8-4354-8f38-6bf46481ffa6.png)

### Generating the Authorization Credentials
* Click CREATE CREDENTIALS, then choose OAuth Client ID
![image](https://user-images.githubusercontent.com/47273077/224525379-9791fa93-c186-4828-a541-f42a818c8687.png)

* Fill in the required fields as shown in the figure below.
![image](https://user-images.githubusercontent.com/47273077/224525569-75f12819-96ee-4910-92da-194134c709da.png)

* Finally, click CREATE. You should have an OAuth client definition for iOS as in the picture below:
![image](https://user-images.githubusercontent.com/47273077/224525597-89d8b3f0-d092-4d1b-845f-fef075ad07b5.png)

* Replace REPLACE_WITH_CLIENTID_FROM_GOOGLE_APP in the definition below with the Client ID from your Google app in PKCERequestBuilder.
![image](https://user-images.githubusercontent.com/47273077/224525620-1ea84c29-3cfa-4f8e-9b8a-e8d198fa763d.png)

### Authenticating the User

```swift
  func startAuthentication() {
    print("[Debug] Start the authentication flow")
    status = .authenticating
    
    // 1
    let codeVerifier = PKCECodeGenerator.generateCodeVerifier()
    guard
      let codeChallenge = PKCECodeGenerator.generateCodeChallenge(
        codeVerifier: codeVerifier
      ),
      // 2
      let authenticationURL = requestBuilder.createAuthorizationRequestURL(
        codeChallenge: codeChallenge
      )
    else {
      print("[Error] Can't build authentication URL!")
      status = .error(error: .internalError)
      return
    }
    print("[Debug] Authentication with: \(authenticationURL.absoluteString)")
    guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
      print("[Error] Bundle Identifier is nil!")
      status = .error(error: .internalError)
      return
    }
    // 3
    let session = ASWebAuthenticationSession(
      url: authenticationURL,
      callbackURLScheme: bundleIdentifier
    ) { callbackURL, error in
      // 4
      self.handleAuthenticationResponse(
        callbackURL: callbackURL,
        error: error,
        codeVerifier: codeVerifier
      )
    }
    // 5
    session.presentationContextProvider = self
    // 6
    session.start()

  }
  ```
  
### You’ll see an alert saying MyGoogleInfo wants to use google.com to sign in
<img width="300" alt="スクリーンショット 2023-03-12 14 47 01" src="https://user-images.githubusercontent.com/47273077/224526780-0c213bdf-284b-421e-b943-d5fe1a0063cc.png">

  
## Tap Continue and you’ll see the Google login screen
![image](https://user-images.githubusercontent.com/47273077/224526610-4bf596e5-7284-41ad-a8ef-
<img width="300" alt="スクリーンショット 2023-03-12 14 47 38" src="https://user-images.githubusercontent.com/47273077/224526809-01bbc74a-61fe-408f-b95d-ddf15e2e181b.png">

