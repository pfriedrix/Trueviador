import Fluent
import Vapor
import JWT


struct Credentials: Codable, Validatable {

    let username: String
    let password: String
    
    
    static func validations(_ validations: inout Validations) {
        validations.add("username", as: String.self, is: .count(3...))
        validations.add("password", as: String.self, is: .count(8...))
    }
}

struct Session: Content {
    let token: String
    let user: String
}

enum OAuthService: String, Codable {
    case github, google
}


final class User: Model, Content {
    struct Public: Content {
        let username: String
        let id: UUID
    }
    
    static let schema = "users"
    
    @ID(key: .id)
    var id: UUID?

    @Field(key: "username")
    var username: String
    
    @Field(key: "hashedPassword")
    var hashedPassword: String
    
    @OptionalEnum(key: "service")
    var service: OAuthService?

    init() { }
    
    init(_ credetials: Credentials) throws {
        self.username = credetials.username
        self.hashedPassword = try BCryptDigest().hash(credetials.password)
    }

    init(id: UUID? = nil, username: String, password: String, service: OAuthService?) throws {
        self.id = id
        self.username = username
        self.hashedPassword = try BCryptDigest().hash(password)
        self.service = service
    }
    
    func matchesPassword(_ password: String) throws -> Bool {
        return try BCryptDigest().verify(password, created: self.hashedPassword)
    }
    
    func createToken(source: SessionSource) throws -> Token {
      let calendar = Calendar(identifier: .gregorian)
        let expiryDate = calendar.date(byAdding: .month, value: 1, to: Date())
      return try Token(
        userId: requireID(),
        token: [UInt8].random(count: 16).base64,
        source: source,
        expiresAt: expiryDate)
    }
    
    func asPublic() throws -> Public {
        Public(username: username, id: try requireID())
    }
}


extension User: ModelAuthenticatable {
    static let usernameKey = \User.$username
    static let passwordHashKey = \User.$hashedPassword
    
    func verify(password: String) throws -> Bool {
        try BCryptDigest().verify(password, created: self.hashedPassword)
    }
}
