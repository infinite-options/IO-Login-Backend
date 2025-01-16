# from flask import request
from data import connect, execute
# from auth import createTokens, createSalt, createHash, getHash

def db_lookup(project):
    print("In db_lookup ", project)

    # Determine the database based on the project
    db_mapping = {
        "PM": "pm",
        "MYSPACE-DEV": "space_dev",
        "MYSPACE": "space_prod",
        "EVERY-CIRCLE": "every_circle",
        "NITYA": "nitya",
        "SKEDUL": "skedul",
        "FINDME": "find_me",
        "MMU": "mmu"
    }
    
    db = db_mapping.get(project)
    if not db:
        raise ValueError(f"Invalid project: {project}")
    print("Database: ", db)

    return db



def user_lookup_query(param, project):
    print("\nIn user_lookup_query ", project, param)

    # Determine the column based on the parameter
    if "@" in param:
        if project in ['MMU', 'EVERY-CIRCLE']:
            column = 'user_email_id'
        else: 
            column = 'email'
    elif "-" in param:
        column = 'user_uid'
    else:
        raise ValueError("Invalid parameter format. Expected an email or user_uid.")

    db = db_lookup(project)

    # Safely construct the query
    query = f"""
        SELECT * 
        FROM {db}.users
        WHERE {column} = \'""" + param + """\';
    """
    print(query)

    conn = connect(db)
    result = execute(query, "get", conn)
    print("Query Result: ", result)

    if result and 'result' in result and len(result['result']) > 0:
        return result['result'][0]
    else:
        return None
