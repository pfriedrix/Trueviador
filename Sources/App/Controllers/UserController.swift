import Fluent
import Vapor

struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        
        auth.post("signup", use: create)
        
        let passwordProtected = auth.grouped(User.authenticator())
        passwordProtected.post("login", use: entry)
        
        let tokenProtected = auth.grouped(Token.authenticator())
        tokenProtected.get("me", use: getUser)
        
        
        
        
        func entry(req: Request) throws -> EventLoopFuture<Session> {
            let user: User = try req.auth.require(User.self)
            let token = try user.createToken(source: .login)
            return token.create(on: req.db)
                .flatMapThrowing {
                    Session(token: token.value, user: user.username)
                }
        }
        
        
        func create(req: Request) throws -> EventLoopFuture<Session> {
            try Credentials.validate(content: req)
            let credentials = try req.content.decode(Credentials.self)
            
            return User.query(on: req.db)
                .filter(\.$username == credentials.username)
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
    }
}


    
