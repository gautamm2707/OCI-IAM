import xlrd
file_location = "/Users/gautamm/Downloads/HelpNow-Data.xlsx"
workbook = xlrd.open_workbook(file_location)
sheet = workbook.sheet_by_index(0)
rows = sheet.nrows
str1 = "client id"

"""for sheet1 in workbook.sheets():
    for rowidxs in range(sheet1.nrows):
        row = sheet1.row(rowidxs)
        for colidxs, cell in enumerate(row):
            if cell.value.find(str1) != -1:
                print (sheet1.name)
                print (colidxs)
                print (rowidxs)"""


data = [[sheet.cell_value(r, 2) for r in range(sheet.nrows)]]
print(type(data))
print(data)


#print(sheet.cell_value(4,2))