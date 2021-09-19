import Fluent
import Vapor

struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        auth.post("login", use: entry)
        auth.post("signup", use: create)
        
        func entry(req: Request) throws -> EventLoopFuture<Response> {
            try Credentials.validate(content: req)
            let credentials = try req.content.decode(Credentials.self)
            
            return User.query(on: req.db)
                .filter(\.$username == credentials.username)
                .first()
                .flatMap { user in
                    do {
                        guard let user = user,
                              try user.matchesPassword(credentials.password)
                        else {
                            throw Abort(.notFound, reason: "Bad Credetials")
                        }
                        let res = req.redirect(to: "/")
                        return req.eventLoop.makeSucceededFuture(res)
                    } catch {
                        return req.eventLoop.makeFailedFuture(error)
                    }
                }
        }
        
        
        func create(req: Request) throws -> EventLoopFuture<Response> {
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
                        newUser.create(on: req.db)
                        
                        let res = req.redirect(to: "/")
                        return req.eventLoop.makeSucceededFuture(res)
                    } catch {
                        return req.eventLoop.makeFailedFuture(error)
                    }
                }
        }
    }
}


    
