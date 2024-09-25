import pandas as pd
df1=pd.read_csv("C:\\Users\gautmish\Downloads\cis_Identity_and_Access_Management_1-12.csv",usecols =['id'])
df2=pd.read_csv("C:\\Users\gautmish\Downloads\cis_Identity_and_Access_Management_1-1.csv",usecols =['id'])
#print(df1.equals(df2))
#len1 = len(df1)
#len2 = len(df2)
#print(len1)
list1 = []
list2 = []
for r2 in df2.id:
        list2.append(r2)
for r1 in df1.id:
        list1.append(r1)
a = set(list1)
b = set(list2)

if a == b:
    print("Lists l1 and l2 are equal")
else:
    print("Lists l1 and l2 are not equal")
