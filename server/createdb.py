import sqlite3
import csv

def create_tables_from_csv(db_name, whitelist_csv, blacklist_csv):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
                     URL TEXT PRIMARY KEY, 
                     label INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
                     URL TEXT PRIMARY KEY, 
                     label INTEGER)''')

    with open(whitelist_csv, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        c.executemany('INSERT OR IGNORE INTO whitelist (URL, label) VALUES (?, ?)', reader)

    with open(blacklist_csv, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        c.executemany('INSERT OR IGNORE INTO blacklist (URL, label) VALUES (?, ?)', reader)

    conn.commit()
    conn.close()

create_tables_from_csv('blacklist_whitelist.db', './csv/whitelist.csv', './csv/blacklist.csv')
