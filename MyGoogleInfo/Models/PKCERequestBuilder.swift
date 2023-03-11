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
