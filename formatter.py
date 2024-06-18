import pandas as pd
from xlsxwriter.utility import xl_rowcol_to_cell

# try for now only with the first sheet
df = pd.read_excel("kubenumerate_results_v1_0.xlsx", "Capabilities - Added")
# https://stackoverflow.com/questions/26521266/using-pandas-to-pd-read-excel-for-multiple-worksheets-of-the-same-workbook
# xls = pd.ExcelFile("kubenumerate_results_v1_0.xlsx")
# xls.sheet_names # list of sheets

with pd.ExcelWriter("enhanced.xlsx", engine="xlsxwriter", mode="w") as writer:
    # df.to_excel(writer, index=False, sheet_name="sheet one")
    workbook = writer.book
    worksheet = workbook.add_worksheet("Capabilities - Added")
    worksheet.set_zoom(90)

    worksheet.set_column(0, len(df.columns)-1, 20)
    header_format = workbook.add_format({
        'font_name': 'Calibri', # Default right now, but including in case changes in the future
        'bg_color': '#A93545',
        'bold': True,
        'font_color': 'white',
        'align': 'left',
    })

    # title = "AppArmor Disabled"
    title = "Capabilities - Added"
    #merge cells
    title_format = workbook.add_format({
        'font_name': 'Calibri',
        'bg_color': '#A93545',
        'font_color': 'white',
        'font_size': 20,
    })
    #
    subtitle = "Capabilities (specifically, Linux capabilities), are used for permission management in Linux. Some capabilities are enabled by default."
    # subtitle = "AppArmor is enabled by adding container.apparmor.security.beta.kubernetes.io/[container name] as a pod-level annotation and setting its value to either runtime/default or a profile (localhost/[profile name])."
    # note down how many cells title and subheader require
    worksheet.merge_range('A1:AC1', title, title_format)
    worksheet.merge_range('A2:AC2', subtitle)
    worksheet.set_row(2, 15) # row height to 15
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(2, col_num, value, header_format)
    worksheet.freeze_panes(3, 0)

    df.to_excel(writer, index=False, sheet_name="Capabilities - Added", startrow=3, header=False)





