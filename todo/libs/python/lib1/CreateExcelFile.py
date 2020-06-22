import xlsxwriter

class ExcelUtility(object):

    def __init__(self):
        print "write to excel file"
    
    def group(self,lst, n):
        """group([0,3,4,10,2,3], 2) => [(0,3), (4,10), (2,3)]
        
        Group a list into consecutive n-tuples. Incomplete tuples are
        discarded e.g.
        
        >>> group(range(10), 3)
        [(0, 1, 2), (3, 4, 5), (6, 7, 8)]
        """
        return zip(*[lst[i::n] for i in range(n)])
    def Write To Excel File(self,filename,content_list):
                
            # Create an new Excel file and add a worksheet.
            workbook = xlsxwriter.Workbook(filename)
            worksheet = workbook.add_worksheet()

            #content_list=[1,1,'hello',2,1,'brother',3,1,'how are you',4,1,'are you good today']
            t=self.group(content_list,3)
            for item in t:
                worksheet.write(int(item[0]), int(item[1]), item[2])
                                                                

            # close work book
            workbook.close()
