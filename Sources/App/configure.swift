import Fluent
import FluentMongoDriver
import Vapor
import JWT


public func configure(_ app: Application) throws {

    try app.databases.use(.mongo(
        connectionString: Environment.get("DATABASE_URL") ?? "mongodb://localhost:27017/trueviador"
    ), as: .mongo)
    
    app.jwt.signers.use(.hs512(key: Environment.get("SECRET") ?? "secret"))
    
    app.migrations.add(CreateTokens())
    app.migrations.add(CreateUser())
    
    app.middleware.use(app.sessions.middleware)

    try routes(app)
}
