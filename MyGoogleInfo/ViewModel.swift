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
import Combine

protocol LoginService {
  func login()
}

class ViewModel: ObservableObject {
  @Published var shouldShowLoginScreen = true
  @Published var givenName: String?
  @Published var familyName: String?
  @Published var pictureURL: URL?

  let authenticationService = PKCEAuthenticationService()
  let profileService = GoogleProfileInfoService()
  var cancellable: AnyCancellable?

  init() {
    cancellable = authenticationService.$status
      .receive(on: DispatchQueue.main)
      .sink { [weak self] authenticationStatus in
        print("[Debug] authentication status: \(authenticationStatus)")

        guard case let .authenticated(token) = authenticationStatus else { return }

        self?.shouldShowLoginScreen = false
        self?.userDidAuthenticateWithToken(token)
      }
  }

  private func userDidAuthenticateWithToken(_ token: GoogleToken) {
    Task {
      let profileInfo = try await profileService.getProfileInfo(token: token.accessToken)
      givenName = profileInfo.givenName
      familyName = profileInfo.familyName
      pictureURL = profileInfo.pictureURL
    }
  }
}

extension ViewModel: LoginService {
  func login() {
    authenticationService.startAuthentication()
  }
}
