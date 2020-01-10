import mysql.connector as sql
import pandas as pd

import pandas as pd
import numpy as np

db_connection = sql.connect(host='localhost', 
                            database='honeyd', 
                            user='root', 
                            password='1234',
                            port='3306')

db_cursor = db_connection.cursor()
db_cursor.execute('SELECT * FROM connections')

table_rows = db_cursor.fetchall()
df = pd.DataFrame(table_rows)

def GetAllData(df):
    df_t = df.T
    df.to_numpy()
    
print(GetAllData(table_rows))