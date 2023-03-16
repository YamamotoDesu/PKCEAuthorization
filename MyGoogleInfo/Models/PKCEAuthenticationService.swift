/// Copyright (c) 2022 Kodeco Inc.
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
/// distribute, sublicense, create a derivative work, and/or sell copies of the
/// Software in any work that is designed, intended, or marketed for pedagogical or
/// instructional purposes related to programming, coding, application development,
/// or information technology.  Permission for such use, copying, modification,
/// merger, publication, distribution, sublicensing, creation of derivative works,
/// or sale is expressly withheld.
/// 
/// This project and source code may use libraries or frameworks that are
/// released under various Open-Source licenses. Use of those libraries and
/// frameworks are governed by their own individual licenses.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

import Foundation
import AuthenticationServices

class PKCEAuthenticationService: NSObject, ObservableObject {
  enum Status: CustomStringConvertible {
    case unauthenticated
    case authenticating
    case authenticated(token: GoogleToken)
    case error(error: AuthenticationError)

    var description: String {
      switch self {
      case .unauthenticated: return "Unauthenticated"
      case .authenticating: return "Authenticating"
      case .authenticated: return "Authenticated"
      case .error(let error): return "Failed with \(error.localizedDescription)"
      }
    }
  }

  enum AuthenticationError: Error {
    case internalError
    case authenticationFailed
    case tokenExchangeFailed
  }

  @Published var status: Status

  private let requestBuilder: PKCERequestBuilder = .myGoogleInfo

  override init() {
    status = .unauthenticated

    super.init()
  }

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

  private func handleAuthenticationResponse(callbackURL: URL?, error: Error?, codeVerifier: String) {
    if let error = error {
      print("[Error] Authentication failed with: \(error.localizedDescription)")
      status = .error(error: .authenticationFailed)
      return
    }
    print("[Debug] Received callback URL: \(callbackURL?.absoluteString ?? "EMPTY")")
    
    guard let code = extractCodeFromCallbackURL(callbackURL) else {
      status = .error(error: .authenticationFailed)
      return
    }
    
    Task {
      await getToken(code: code, codeVerifier: codeVerifier)
    }
  }

  private func extractCodeFromCallbackURL(_ callbackURL: URL?) -> String? {
    guard let callbackURL = callbackURL else {
      print("[Error] CallbackURL is nil!")
      return nil
    }

    print("[Debug] Callback received from authentication: \(callbackURL.absoluteString)")

    let urlComponents = URLComponents(string: callbackURL.absoluteString)
    guard
      let queryItems = urlComponents?.queryItems,
      let code = queryItems.first(where: { $0.name == "code" })?.value else {
      print("[Error] Callback URL parsing failed!")
      return nil
    }

    return code
  }
  
  private func getToken(code: String, codeVerifier: String) async {
    guard let tokenURLRequest = requestBuilder.createTokenExchangeURLRequest(
      code: code,
      codeVerifier: codeVerifier
    ) else {
      print("[Error] Can't build token exchange URL!")
      status = .error(error: .internalError)
      return
    }
    let tokenURLRequestBody = tokenURLRequest.httpBody ?? Data()
      print("[Debug] Get token parameters: \(String(data: tokenURLRequestBody, encoding: .utf8) ?? "")")
    do {
      let (data, response) = try await URLSession.shared.data(for: tokenURLRequest)

      guard let response = response as? HTTPURLResponse else {
        print("[Error] HTTP response parsing failed!")
        status = .error(error: .tokenExchangeFailed)
        return
      }

      guard response.isOk else {
        let body = String(data: data, encoding: .utf8) ?? "EMPTY"
        print("[Error] Get token failed with status: \(response.statusCode), body: \(body)")
        status = .error(error: .tokenExchangeFailed)
        return
      }

      print("[Debug] Get token response: \(String(data: data, encoding: .utf8) ?? "EMPTY")")

      let decoder = JSONDecoder()
      decoder.keyDecodingStrategy = .convertFromSnakeCase
      let token = try decoder.decode(GoogleToken.self, from: data)

      // TODO: Store the token in the Keychain
      status = .authenticated(token: token)
    } catch {
      print("[Error] Get token failed with: \(error.localizedDescription)")
      status = .error(error: .tokenExchangeFailed)
    }
  }
}

extension PKCEAuthenticationService: ASWebAuthenticationPresentationContextProviding {
  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    return ASPresentationAnchor()
  }
}

private extension HTTPURLResponse {
  var isOk: Bool { 200..<300 ~= statusCode }
}
