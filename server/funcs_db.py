import sqlite3


def check_blacklist(db_name, url):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT EXISTS(SELECT 1 FROM blacklist WHERE URL=?)', (url,))
    result = c.fetchone()[0]
    conn.close()
    return bool(result)

def check_whitelist(db_name, url):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('SELECT EXISTS(SELECT 1 FROM whitelist WHERE URL=?)', (url,))
    result = c.fetchone()[0]
    conn.close()
    return bool(result)

def add_to_blacklist(db_name, url, label=0):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO blacklist (URL, label) VALUES (?, ?)', (url, label))
    conn.commit()
    conn.close()

def add_to_whitelist(db_name, url, label=1):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO whitelist (URL, label) VALUES (?, ?)', (url, label))
    conn.commit()
    conn.close()

def delete_from_blacklist(db_name, url):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('DELETE FROM blacklist WHERE URL=?', (url,))
    conn.commit()
    conn.close()

def delete_from_whitelist(db_name, url):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('DELETE FROM whitelist WHERE URL=?', (url,))
    conn.commit()
    conn.close()
