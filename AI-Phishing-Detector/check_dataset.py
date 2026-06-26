import pandas as pd

df = pd.read_csv("phishing_emails.csv")

print(df.head())
print(df.columns)
print(df.shape)