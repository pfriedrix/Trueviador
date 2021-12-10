import Vapor

struct GitHubUserInfo: Decodable, Content {
    let login: String
}

struct GitHubTokens {
    let client_id: String
    let client_secret: String
    
    init () throws {
        self.client_id = Environment.get("GITHUB_CLIENT_ID") ?? "NONE"
        self.client_secret = Environment.get("GITHUB_CLIENT_SECRET") ?? "NONE"
    }
}

struct GitHubAccesToken: Decodable {
    let access_token: String
}

struct GitHubAuth {
    let tokens: GitHubTokens
    
    init () throws {
        self.tokens = try GitHubTokens()
    }
    
    func authURL() throws -> String {
        
        var components = URLComponents()
        components.scheme = "https"
        components.host = "github.com"
        components.path = "/login/oauth/authorize"
        components.queryItems = [
            URLQueryItem(name: "client_id", value: self.tokens.client_id),
        ]
        
        guard let url = components.url else {
            throw Abort(.internalServerError)
        }
        
        return url.absoluteString
    }
    
    func accessTokenURL(code: String) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "github.com"
        components.path = "/login/oauth/access_token"
        components.queryItems = [
            URLQueryItem(name: "client_id", value: self.tokens.client_id),
            URLQueryItem(name: "client_secret", value: self.tokens.client_secret),
            URLQueryItem(name: "code", value: code)
        ]
        
        guard let url = components.url else {
            throw Abort(.internalServerError)
        }
        
        return url
    }
    
    static func getUser(on request: Request, with token: String) throws -> EventLoopFuture<GitHubUserInfo> {
        let githubUserAPIURL = "https://api.github.com/user"
        return request
            .client
            .get(URI(string: githubUserAPIURL), headers: ["Authorization": "Bearer \(token)", "User-Agent": "request"])
            .flatMap { response -> EventLoopFuture<GitHubUserInfo> in
                do {
                    let userInfo = try response.content
                        .decode(GitHubUserInfo.self)
                    return request.eventLoop.makeSucceededFuture(userInfo)
                }
                catch {
                    return request.eventLoop.makeFailedFuture(error)
                }
                
            }
    }
}

