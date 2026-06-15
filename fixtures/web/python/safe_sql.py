def run_query(user_input, db):
    query = "SELECT * FROM users WHERE name = %s"
    return db.execute(query, [user_input])

