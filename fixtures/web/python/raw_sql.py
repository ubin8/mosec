def run_query(user_input, db):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return db.execute(query)

