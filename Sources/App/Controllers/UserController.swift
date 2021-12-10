import Fluent
import Vapor


struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        let oauth = routes.grouped("oauth")
        
        oauth.group("github") { github in
            github.get("login") { req -> EventLoopFuture<Response> in
                let resp = try req.redirect(to: GitHubAuth().authURL())
                return req.eventLoop.makeSucceededFuture(resp)
            }
            github.get("", use: processGitHubLogin)
        }
        
        auth.post("signup", use: create)
        
        let passwordProtected = auth.grouped(User.authenticator())
        passwordProtected.post("login", use: entry)
        
        let tokenProtected = auth.grouped(Token.authenticator())
        tokenProtected.get("me", use: getUser)
        
        func entry(req: Request) throws -> EventLoopFuture<Session> {
            try Credentials.validate(content: req)
            let credentials = try req.content.decode(Credentials.self)
            return User
                .query(on: req.db)
                .filter(\.$username == credentials.username)
                .filter(\.$service == nil)
                .first().flatMap { foundUser in
                    do {
                        guard let user = foundUser else { return req.eventLoop.makeFailedFuture(Abort(.unauthorized)) }
                        req.auth.login(user)
                        let token = try user.createToken(source: .login)
                        return token.create(on: req.db)
                            .flatMapThrowing {
                                Session(token: token.value, user: user.username)
                            }
                    } catch {
                        return req.eventLoop.makeFailedFuture(error)
                    }
                }
        }
        
        
        func create(req: Request) throws -> EventLoopFuture<Session> {
            try Credentials.validate(content: req)
            let credentials = try req.content.decode(Credentials.self)
            
            return User.query(on: req.db)
                .filter(\.$username == credentials.username)
                .filter(\.$service == nil)
                .first()
                .flatMap { user in
                    do {
                        guard user == nil
                        else {
                            throw Abort(.badRequest, reason: "User Exists")
                        }
                        let newUser = try User(credentials)
                        let _ = newUser.create(on: req.db)
                        guard let newToken = try? newUser.createToken(source: .signup) else {
                            return req.eventLoop.future(error: Abort(.internalServerError))
                        }
                        let _ = newToken.create(on: req.db)
                        return req.eventLoop.makeSucceededFuture(Session(token: newToken.value, user: newUser.username))
                        
                    } catch {
                        return req.eventLoop.makeFailedFuture(error)
                    }
                }
        }
        
        func getUser(req: Request) throws -> User.Public {
            try req.auth.require(User.self).asPublic()
        }
        
        func processGitHubLogin(req: Request) throws -> EventLoopFuture<Session> {
            guard let code = req.query[String.self, at: "code"] else {
                throw Abort(.badRequest)
            }
            let url = try GitHubAuth().accessTokenURL(code: code)
            return req.client.post(URI(string: url.absoluteString)).flatMap { resp -> EventLoopFuture<Session> in
                do {
                    let accessToken = try resp.content.decode(GitHubAccesToken.self)
                    return try GitHubAuth.getUser(on: req, with: accessToken.access_token)
                        .flatMap { userInfo in
                            return User.query(on: req.db)
                                .filter(\.$username == userInfo.login)
                                .filter(\.$service == .github)
                                .first()
                                .flatMap { foundUser in
                                    do {
                                        guard foundUser != nil else {
                                            let user = try User(
                                                username: userInfo.login,
                                                password: UUID().uuidString,
                                                service: .github)
                                            let _ = user.create(on: req.db)
                                            guard let newToken = try? user.createToken(source: .signup) else {
                                                return req.eventLoop.makeFailedFuture(Abort(.internalServerError))
                                            }
                                            let _ = newToken.create(on: req.db)
                                            return req.eventLoop.makeSucceededFuture(Session(token: newToken.value, user: user.username))
                                        }
                                        let user: User = try req.auth.require(User.self)
                                        let token = try user.createToken(source: .login)
                                        return token.create(on: req.db)
                                            .flatMapThrowing {
                                                Session(token: token.value, user: user.username)
                                            }
                                    } catch {
                                        return req.eventLoop.makeFailedFuture(error)
                                    }
                                    
                                    
                                }
                        }
                } catch {
                    return req.eventLoop.makeFailedFuture(error)
                }
            }
        }
    }
}
}



