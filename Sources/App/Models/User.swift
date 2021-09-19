import Fluent
import Vapor


struct Credentials: Codable, Validatable {

    let username: String
    let password: String
    
    
    static func validations(_ validations: inout Validations) {
        validations.add("username", as: String.self, is: .count(3...))
        validations.add("password", as: String.self, is: .count(8...))
    }
}


final class User: Model, Content {
    static let schema = "users"
    
    @ID(key: .id)
    var id: UUID?

    @Field(key: "username")
    var username: String
    
    @Field(key: "hashedPassword")
    var hashedPassword: String

    init() { }
    
    init(_ credetials: Credentials) throws {
        self.username = credetials.username
        self.hashedPassword = try BCryptDigest().hash(credetials.password)
    }

    init(id: UUID? = nil, username: String, password: String) throws {
        self.id = id
        self.username = username
        self.hashedPassword = try BCryptDigest().hash(password)
    }
    
   public func matchesPassword(_ password: String) throws -> Bool {
        return try BCryptDigest().verify(password, created: self.hashedPassword)
    }
}

