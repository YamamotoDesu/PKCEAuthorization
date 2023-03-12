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
