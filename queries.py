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
        "MMU": "mmu",
        "SIGNUP":"signup"
    }
    
    db = db_mapping.get(project)
    if not db:
        raise ValueError(f"Invalid project: {project}")
    print("Database: ", db)

    return db



def user_lookup_query(param, db):
    print("\nIn user_lookup_query ", db, param)
    param = str(param)

    print("About to enter if block", param, type(param))
    # Determine the column based on the parameter
    if "@" in param:
        if db in ['space_dev', 'space_prod', 'pm']:
            column = 'email'
        else: 
            column = 'user_email_id'
    elif "-" in param:
        column = 'user_uid'
    elif "." in param:
        column = 'user_social_id'
    else:
        print("In else.  Invalid parameter")
        raise ValueError("Invalid parameter format. Expected an email or user_uid.")
        # return None

    print("Past check. ", column)
    # db = db_lookup(project)

    # Safely construct the query
    query = f"""
        SELECT * 
        FROM {db}.users
        WHERE {column} = \'""" + param + """\';
    """
    # print(query)

    conn = connect(db)
    result = execute(query, "get", conn)
    # print("Query Result: ", result)

    if result and 'result' in result and len(result['result']) > 0:
        return result['result'][0]
    else:
        return None
