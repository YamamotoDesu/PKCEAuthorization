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

struct GoogleProfileInfoService {
  enum ServiceError: Error {
    case responseError
    case serverError(status: Int)
  }

  @MainActor
  func getProfileInfo(token: String) async throws -> GoogleProfileInfo {
    // swiftlint:disable:next force_unwrapping
    var urlRequest = URLRequest(url: URL(string: "https://www.googleapis.com/userinfo/v2/me")!)
    urlRequest.httpMethod = "GET"
    urlRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

    let (data, response) = try await URLSession.shared.data(for: urlRequest)

    guard let response = response as? HTTPURLResponse else {
      print("[Error] HTTP response parsing failed!")
      throw ServiceError.responseError
    }

    // TODO: Here we want to check if status is 401 (Unauthorized) and, if yes, trigger a token refresh
    guard response.statusCode == 200 else {
      print("[Error] Server response status: \(response.statusCode)")
      throw ServiceError.serverError(status: response.statusCode)
    }

    let profileInfo = try JSONDecoder().decode(GoogleProfileInfo.self, from: data)
    print("[Debug] Downloaded profile info for: \(profileInfo.name)")
    return profileInfo
  }
}
