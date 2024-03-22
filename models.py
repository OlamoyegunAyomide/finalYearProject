import uuid
class users:
    def __init__(self, user_id= None, full_name=None, email_address=None, password=None):
        self.user_id= user_id if user_id else uuid.uuid4().hex
        self.full_name = full_name
        self. email_address = email_address
        self.role = role
        self.password = password

    def __str__(self):
        return f"user_id: {self.user_id};"\
                f"full_name: {self.full_name}; "\
                f"email_address: {self.email_address}; "\
                f"role: {self.role}; "\
                f"password: {self.password}"
    
class user_input:
    def __init__(self, input_id=None, user_id=None, input=None, created_at=None):
        self.input_id = input_id if input_id else uuid.uuid4().hex
        self.user_id = user_id
        self.input = input
        self.created_at = created_at

    def __str__(self):
        return f"input_id: {self.input_id}; "\
                f"user_id: {self.user_id}; "\
                f"input: {self.input}; "\
                f"created_at: {self.created_at}"

class generated_requirements:
    def __init__(self, requirement_id=None, input_id=None, requirement=None, created_at=None):
        self.requirement_id = requirement_id if requirement_id else uuid.uuid4().hex
        self.input_id = input_id
        self.requirement = requirement
        self.created_at = created_at
    
    def __str__(self):
        return f"requirement_id: {self.requirement_id}; "\
                f"input_id: {self.input_id}; "\
                f"requirement: {self.requirement}; "\
                f"created_at: {self.created_at}"
