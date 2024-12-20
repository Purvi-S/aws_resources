import pandas
df = pandas.read_parquet('**Path**', engine='pyarrow')
print(df)