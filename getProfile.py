from data import connect, disconnect, serializeResponse, execute



def getBusinessProfileInfo(user, projectName):
    print("In Business Profile Info")
    # print(projectName, user)

    if projectName == 'PM':
        response = {}
        conn = connect('pm')
        query = """SELECT b.*, e.employee_role
            FROM employees e LEFT JOIN businesses b ON e.business_uid = b.business_uid
            WHERE user_uid = \'""" + user['user_uid'] + """\'"""

        response = execute(query, "get", conn)
        return response
    elif projectName == "MYSPACE-DEV":
       
        response = {}
        conn = connect('space_dev')
        query = """
            SELECT business_uid, business_type, employee_uid, employee_role 
            FROM space_dev.employees
            LEFT JOIN space_dev.businessProfileInfo ON employee_business_id = business_uid
            WHERE employee_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        # print(response)
        if "result" not in response:
            response["result"] = None
        else:
            businesses = {
                'MAINTENANCE': {},
                'MANAGEMENT': {}
            }
            key_map = {
                'MAINTENANCE': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id'
                },
                'MANAGEMENT': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id' 
                }
            }
            for record in response["result"]:
                # print(record)
                role_key = key_map[record['business_type']][record['employee_role']]
                # print("Role Key: ", role_key)
                businesses[record['business_type']].update({
                    role_key: record['employee_uid'],
                    'business_uid': record['business_uid']
                })
            response["result"] = businesses
        return response
    
    elif projectName == "MYSPACE":
        
        response = {}
        conn = connect('space_prod')
        query = """
            SELECT business_uid, business_type, employee_uid, employee_role 
            FROM space_prod.employees
            LEFT JOIN space_prod.businessProfileInfo ON employee_business_id = business_uid
            WHERE employee_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        if "result" not in response:
            response["result"] = None
        else:
            businesses = {
                'MAINTENANCE': {},
                'MANAGEMENT': {}
            }
            key_map = {
                'MAINTENANCE': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id'
                },
                'MANAGEMENT': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id' 
                }
            }
            for record in response["result"]:
                role_key = key_map[record['business_type']][record['employee_role']]
                businesses[record['business_type']].update({
                    role_key: record['employee_uid'],
                    'business_uid': record['business_uid']
                })
            response["result"] = businesses
        return response

def getOwnerProfileInfo(user, projectName):
    print("In Owner Profile Info")
    
    if projectName == 'MYSPACE-DEV':
        
        response = {}
        conn = connect('space_dev')
        query = """
            SELECT owner_uid 
            FROM space_dev.ownerProfileInfo 
            WHERE owner_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["owner_uid"]
        return response
    if projectName == 'MYSPACE':
        
        response = {}
        conn = connect('space_prod')
        query = """
            SELECT owner_uid 
            FROM space_prod.ownerProfileInfo 
            WHERE owner_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["owner_uid"]
        return response

def getTenantProfileInfo(user, projectName):
    print("In Tenant Profile Info")
    
    if projectName == 'PM':
        response = {}
        conn = connect('pm')
        query = """ SELECT tenant_id FROM tenantProfileInfo
                WHERE tenant_user_id = \'""" + user['user_uid'] + """\'"""

        response = execute(query, "get", conn)
        return response
    elif projectName == "MYSPACE-DEV":
        
        response = {}
        conn = connect('space_dev')
        query = """
            SELECT tenant_uid 
            FROM space_dev.tenantProfileInfo 
            WHERE tenant_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["tenant_uid"]
        return response
    elif projectName == "MYSPACE":
        
        response = {}
        conn = connect('space_prod')
        query = """
            SELECT tenant_uid 
            FROM space_prod.tenantProfileInfo 
            WHERE tenant_user_id = \'""" + user['user_uid'] + """\'
            """
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["tenant_uid"]
        return response
    
