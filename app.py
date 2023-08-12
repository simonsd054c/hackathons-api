from flask import Flask, request #, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
app = Flask(__name__)
ma = Marshmallow(app)

# what dbms + db adapter + db_user + password + host:port + database name
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://hackathon_db_admin:password123@localhost:5432/hackathon_db_flask"
app.config["JWT_SECRET_KEY"] = "secret"

#create the database instance
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.cli.command("create")
def create_tables():
    db.create_all()
    print("tables created")

@app.cli.command("seed")
def seed_tables():

    members = [
        Member(
            username = "admin",
            email = "admin@email.com",
            password = bcrypt.generate_password_hash("password123").decode('utf-8'),
            role = "Student",
            age = 32,
            is_admin = True
        ),
        Member(
            username = 'user1',
            email = 'user1@email.com',
            password = bcrypt.generate_password_hash("password123").decode('utf-8'),
            role = "Lead Developer",
            age = 38
        )
    ]

    db.session.add_all(members)

    project1 = Project(
        title = 'Brisbane Traffic Solver',
        repository = 'https://github.com/traffic_team/traffic_solver', 
        description = 'description goes here...'
    )
    db.session.add(project1)

    project2 = Project(
        title = 'Sustainability coding board game',
        repository = 'https://github.com/ca_team/coding_board_game', 
        description = 'description goes here...'
    )
    db.session.add(project2)
    db.session.commit()
    print("tables seeded")

@app.cli.command('drop')
def drop_tables():
    db.drop_all()
    print("tables dropped")

class Project(db.Model):
    __tablename__ = "projects"
    
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String())
    repository = db.Column(db.String())
    description = db.Column(db.String())

class ProjectSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "repository", "description")

projects_schema = ProjectSchema(many=True)
project_schema = ProjectSchema()


class Member(db.Model):
    __tablename__ = "members"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    role = db.Column(db.String(), default="Developer")
    age = db.Column(db.Integer)
    is_admin = db.Column(db.Boolean, default=False)

class MemberSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "email", "password", "role", "age", "is_admin")
        load_only = ("password",)

members_schema = MemberSchema(many=True)
member_schema = MemberSchema()


@app.route('/')
def welcome():
    return "Welcome students to the hackathon!"

#@app.route('/projects', methods=["GET"])
#@app.route('/projects')
@app.get('/projects')
def get_projects():
    #prepare the query to get data SELECT * FROM PROJECTS
    stmt = db.select(Project)
    #get the data
    projects = db.session.scalars(stmt)
    #convert the db data into something readable by Python
    result = projects_schema.dump(projects)

    return result
    #return jsonify(result)

@app.get('/projects/<int:id>/')
def get_project_by_id(id):
    #prepare the query to get data SELECT * FROM PROJECTS WHERE ID = :id
    stmt = db.select(Project).filter_by(id = id)
    #get the data
    project = db.session.scalar(stmt)

    if project:
        #convert the db data into something readable by Python
        return project_schema.dump(project)
    else:
        return {'error' : f'Project not found with id {id}'}, 404

#@app.route('/projects', methods=["POST"])
@app.post('/projects')
@jwt_required()
def create_project():
   #create a project
   #print(request.json)
   project_fields = project_schema.load(request.json)
   new_project = Project(
        title = project_fields["title"],
        repository = project_fields["repository"], 
        description = project_fields["description"]
    )
   db.session.add(new_project)
   db.session.commit() 
   return project_schema.dump(new_project), 201

@app.delete('/projects/<int:id>')
@jwt_required()
def delete_project(id):

    if not authorise_as_admin():
        return {'error': 'Not authorised to delete a project'}, 403

    stmt = db.select(Project).filter_by(id = id)
    project = db.session.scalar(stmt)

    if project:
        db.session.delete(project)
        db.session.commit()
        return {'message': f"Project {project.title} deleted successfully"}, 202
    else:
        return {'error': f"Project not found with id {id}"}, 404
    
# @app.put
@app.route('/projects/<int:id>', methods=["PUT", "PATCH"])
def update_project(id):
    stmt = db.select(Project).filter_by(id = id)
    project = db.session.scalar(stmt)

    if project:
        project.title = request.json.get("title") or project.title
        project.repository = request.json.get("repository") or project.repository 
        project.description = request.json.get("description") or project.description

        db.session.commit()
        return project_schema.dump(project), 202

    else:
        return {'error': f"Project not found with id {id}"}, 404
    

@app.post("/auth/register")
def register_member():
    member_fields = member_schema.load(request.get_json())
    password = member_fields.get("password")
    new_member = Member(
        username = member_fields.get("username"),
        email = member_fields.get("email"),
        password = bcrypt.generate_password_hash(password).decode('utf-8'),
        role = member_fields.get("role"),
        age = member_fields.get("age")
    )
    db.session.add(new_member)
    db.session.commit()
    return member_schema.dump(new_member), 201

@app.post("/auth/login")
def login_member():
    # Find a member with that email address
    stmt = db.select(Member).filter_by(email=request.get_json().get("email"))
    member = db.session.scalar(stmt)
    # If member exists and password also matches
    if member and bcrypt.check_password_hash(member.password, request.get_json().get("password")):

        # create the token and return it
        token = create_access_token(identity=(str(member.id)), expires_delta=timedelta(days=1))
        return {'email': member.email, 'token': token, 'is_admin': member.is_admin}

    # else
    else:
        # return error message
        return {'error': 'Invalid email or password'}, 401
    

def authorise_as_admin():
    '''
    return true if the requesting user is an admin
    return false if the requesting user is not an admin
    '''
    member_id = get_jwt_identity()
    stmt = db.select(Member).filter_by(id=member_id)
    member = db.session.scalar(stmt)
    return member.is_admin