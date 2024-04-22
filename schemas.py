from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    quote = fields.Str(required=False)

# input for /login endpoint
class UserLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)

# response for /protected endpoint
class UserProtectedSchema(Schema):
    username = fields.Str(required=True)
    quote = fields.Str()
